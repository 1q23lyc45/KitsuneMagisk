#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <set>

#include <consts.hpp>
#include <base.hpp>
#include <db.hpp>
#include <core.hpp>

#include "deny.hpp"

using namespace std;

atomic_flag skip_pkg_rescan;

atomic_flag *p_skip_pkg_rescan = &skip_pkg_rescan;

bool sulist_enabled = false;
static const char *table_name = "hidelist";

// For the following data structures:
// If package name == ISOLATED_MAGIC, or app ID == -1, it means isolated service

// Package name -> list of process names
static unique_ptr<map<string, set<string, StringCmp>, StringCmp>> pkg_to_procs_;
#define pkg_to_procs (*pkg_to_procs_)

// app ID -> list of pkg names (string_view points to a pkg_to_procs key)
static unique_ptr<map<int, set<string_view>>> app_id_to_pkgs_;
#define app_id_to_pkgs (*app_id_to_pkgs_)

// Locks the data structures above
static pthread_mutex_t data_lock = PTHREAD_MUTEX_INITIALIZER;

atomic<bool> denylist_enforced = false;

#define do_kill (denylist_enforced)

static bool add_hide_set(const char *pkg, const char *proc);

void rescan_apps() {
    LOGD("denylist: rescanning apps\n");

    if (sulist_enabled){
        db_strings str;
        get_db_strings(str, SU_MANAGER);
        string manager_pkg = (str[SU_MANAGER].empty())?
            JAVA_PACKAGE_NAME : str[SU_MANAGER];
        add_hide_set(manager_pkg.data(), manager_pkg.data());
    }
    

    app_id_to_pkgs.clear();

    auto data_dir = xopen_dir(APP_DATA_DIR);
    if (!data_dir)
        return;
    dirent *entry;
    while ((entry = xreaddir(data_dir.get()))) {
        // For each user
        int dfd = xopenat(dirfd(data_dir.get()), entry->d_name, O_RDONLY);
        if (auto dir = xopen_dir(dfd)) {
            while ((entry = xreaddir(dir.get()))) {
                struct stat st{};
                // For each package
                if (xfstatat(dfd, entry->d_name, &st, 0))
                    continue;
                int app_id = to_app_id(st.st_uid);
                if (auto it = pkg_to_procs.find(entry->d_name); it != pkg_to_procs.end()) {
                    app_id_to_pkgs[app_id].insert(it->first);
                }
            }
        } else {
            close(dfd);
        }
    }
}

static void update_pkg_uid(const string &pkg, bool remove) {
    auto data_dir = xopen_dir(APP_DATA_DIR);
    if (!data_dir)
        return;
    dirent *entry;
    struct stat st{};
    char buf[PATH_MAX] = {0};
    // For each user
    while ((entry = xreaddir(data_dir.get()))) {
        ssprintf(buf, sizeof(buf), "%s/%s", entry->d_name, pkg.data());
        if (fstatat(dirfd(data_dir.get()), buf, &st, 0) == 0) {
            int app_id = to_app_id(st.st_uid);
            if (remove) {
                if (auto it = app_id_to_pkgs.find(app_id); it != app_id_to_pkgs.end()) {
                    it->second.erase(pkg);
                    if (it->second.empty()) {
                        app_id_to_pkgs.erase(it);
                    }
                }
            } else {
                app_id_to_pkgs[app_id].insert(pkg);
            }
            break;
        }
    }
}

static set<string> get_users() {
    set<string> result { "0" };
    auto data_dir = xopen_dir(APP_DATA_DIR);
    if (!data_dir)
        return result;
    dirent *entry;
    struct stat st{};
    char buf[PATH_MAX] = {0};
    // For each user
    while ((entry = xreaddir(data_dir.get()))) {
        result.insert(entry->d_name);
    }
    return result;
}

// Leave /proc fd opened as we're going to read from it repeatedly
static DIR *procfp;

void crawl_procfs(const std::function<bool(int)> &fn) {
    rewinddir(procfp);
    dirent *dp;
    int pid;
    while ((dp = readdir(procfp))) {
        pid = parse_int(dp->d_name);
        if (pid > 0 && !fn(pid))
            break;
    }
}

static inline bool str_eql(string_view a, string_view b) { return a == b; }


int new_daemon_thread(void(*entry)()) {
    thread_entry proxy = [](void *entry) -> void * {
        reinterpret_cast<void(*)()>(entry)();
        return nullptr;
    };
    return new_daemon_thread(proxy, (void *) entry);
}

template<bool str_op(string_view, string_view) = &str_eql>
static bool proc_name_match(int pid, string_view name) {
    char buf[4019];
    sprintf(buf, "/proc/%d/cmdline", pid);
    if (auto fp = open_file(buf, "re")) {
        fgets(buf, sizeof(buf), fp.get());
        if (str_op(buf, name)) {
            return true;
        }
    }
    return false;
}

static bool proc_context_match(int pid, string_view context) {
    char buf[PATH_MAX];
    sprintf(buf, "/proc/%d/attr/current", pid);
    if (auto fp = open_file(buf, "re")) {
        fgets(buf, sizeof(buf), fp.get());
        if (str_starts(buf, context)) {
            return true;
        }
    }
    return false;
}

template<bool matcher(int, string_view) = &proc_name_match>
static void kill_process(const char *name, bool multi = false) {
    crawl_procfs([=](int pid) -> bool {
        if (matcher(pid, name)) {
            kill(pid, SIGKILL);
            LOGD("denylist: kill PID=[%d] (%s)\n", pid, name);
            return multi;
        }
        return true;
    });
}

static bool validate(const char *pkg, const char *proc) {
    bool pkg_valid = false;
    bool proc_valid = true;

    if (str_eql(pkg, ISOLATED_MAGIC)) {
        pkg_valid = true;
        for (char c; (c = *proc); ++proc) {
            if (isalnum(c) || c == '_' || c == '.')
                continue;
            if (c == ':')
                break;
            proc_valid = false;
            break;
        }
    } else {
        for (char c; (c = *pkg); ++pkg) {
            if (isalnum(c) || c == '_')
                continue;
            if (c == '.') {
                pkg_valid = true;
                continue;
            }
            pkg_valid = false;
            break;
        }

        for (char c; (c = *proc); ++proc) {
            if (isalnum(c) || c == '_' || c == ':' || c == '.')
                continue;
            proc_valid = false;
            break;
        }
    }
    return pkg_valid && proc_valid;
}

static bool add_hide_set(const char *pkg, const char *proc) {
    auto p = pkg_to_procs[pkg].emplace(proc);
    if (!p.second)
        return false;
    LOGI("%s add: [%s/%s]\n", table_name, pkg, proc);
    if (!do_kill)
        return true;
    if (str_eql(pkg, ISOLATED_MAGIC)) {
        // Kill all matching isolated processes
        kill_process<&proc_name_match<str_starts>>(proc, true);
    } else {
        kill_process(proc);
    }
    return true;
}

static void clear_data() {
    pkg_to_procs_.reset(nullptr);
    app_id_to_pkgs_.reset(nullptr);
}

static bool ensure_data() {
    if (pkg_to_procs_)
        return true;

    LOGI("%s: initializing internal data structures\n", table_name);

    default_new(pkg_to_procs_);
    string select_from_cmd = string("SELECT * FROM ") + table_name;
    char *err = db_exec(select_from_cmd.data(), [](db_row &row) -> bool {
        add_hide_set(row["package_name"].data(), row["process"].data());
        return true;
    });
    db_err_cmd(err, goto error)

    default_new(app_id_to_pkgs_);
    rescan_apps();

    return true;

error:
    clear_data();
    return false;
}

static int add_list(const char *pkg, const char *proc) {
    if (proc[0] == '\0')
        proc = pkg;

    if (!validate(pkg, proc))
        return DenyResponse::INVALID_PKG;

    {
        mutex_guard lock(data_lock);
        if (!ensure_data())
            return DenyResponse::ERROR;
        if (!add_hide_set(pkg, proc))
            return DenyResponse::ITEM_EXIST;
        auto it = pkg_to_procs.find(pkg);
        update_pkg_uid(it->first, false);
    }

    // Add to database
    char sql[4096];
    ssprintf(sql, sizeof(sql),
            "INSERT INTO %s (package_name, process) VALUES('%s', '%s')", table_name, pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DenyResponse::ERROR)
    return DenyResponse::OK;
}

int add_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return add_list(pkg.data(), proc.data());
}

static int rm_list(const char *pkg, const char *proc) {
    {
        mutex_guard lock(data_lock);
        if (!ensure_data())
            return DenyResponse::ERROR;

        bool remove = false;

        auto it = pkg_to_procs.find(pkg);
        if (it != pkg_to_procs.end()) {
            if (proc[0] == '\0') {
                update_pkg_uid(it->first, true);
                pkg_to_procs.erase(it);
                remove = true;
                LOGI("%s rm: [%s]\n", table_name, pkg);
            } else if (it->second.erase(proc) != 0) {
                remove = true;
                LOGI("%s rm: [%s/%s]\n", table_name, pkg, proc);
                if (it->second.empty()) {
                    update_pkg_uid(it->first, true);
                    pkg_to_procs.erase(it);
                }
            }
        }

        if (!remove)
            return DenyResponse::ITEM_NOT_EXIST;
    }

    char sql[4096];
    if (proc[0] == '\0')
        ssprintf(sql, sizeof(sql), "DELETE FROM %s WHERE package_name='%s'", table_name, pkg);
    else
        ssprintf(sql, sizeof(sql),
                "DELETE FROM %s WHERE package_name='%s' AND process='%s'", table_name, pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DenyResponse::ERROR)
    return DenyResponse::OK;
}

int rm_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return rm_list(pkg.data(), proc.data());
}

void ls_list(int client) {
    {
        mutex_guard lock(data_lock);
        if (!ensure_data()) {
            write_int(client, static_cast<int>(DenyResponse::ERROR));
            return;
        }

        set<string> users = get_users();
        set<string> pkgs_to_rm;
        set<string> isolated_procs_to_rm;
    
        // Find the packages that are not installed and remove them from list
        for (const auto &[pkg, procs] : pkg_to_procs) {
            // Isolated process
            if (pkg == ISOLATED_MAGIC) {
                // Find the isolated processes not associated with any app id and remove them from the list
                for (const auto &proc : procs) {
                    // Check if the process is not associated with any app id
                    for (const auto &[app_id, pkgs] : app_id_to_pkgs)
                    for (const auto &pkg_ : pkgs)
                    if (str_starts(proc, pkg_))
                        goto skip_rm_isolate_proc;
                    // If not associated, remove it from the list
                    isolated_procs_to_rm.insert(proc);
    
                    skip_rm_isolate_proc:
                    continue;
                }
                continue;
            }
    
            // For every package name of app
            for (const auto &user : users) {
                string app_data_dir = string(APP_DATA_DIR) + "/" + user + "/" + pkg;
                if (access(app_data_dir.data(), F_OK) == 0)
                    goto skip_rm_pkg;
            }
            pkgs_to_rm.insert(pkg);
            
            skip_rm_pkg:
            continue;
        }
    
        char sql[4096];
        for (const auto &pkg : pkgs_to_rm) {
            if (auto it = pkg_to_procs.find(pkg); it != pkg_to_procs.end()) {
                update_pkg_uid(it->first, true);
                pkg_to_procs.erase(it);
                LOGI("%s rm: [%s]\n", table_name, pkg.data());
            }
            ssprintf(sql, sizeof(sql), "DELETE FROM %s WHERE package_name='%s'", table_name, pkg.data());
            db_exec(sql);
        }
    
        if (auto it = pkg_to_procs.find(ISOLATED_MAGIC); it != pkg_to_procs.end()) {
            for (const auto &proc : isolated_procs_to_rm) {
                if (it->second.erase(proc) != 0) {
                    LOGI("%s rm: [%s/%s]\n", table_name, ISOLATED_MAGIC, proc.data());
                    if (it->second.empty()) {
                        pkg_to_procs.erase(it);
                    }
                }
                ssprintf(sql, sizeof(sql),
                    "DELETE FROM %s WHERE package_name='%s' AND process='%s'", table_name, ISOLATED_MAGIC, proc.data());
                db_exec(sql);
            }
        }

        write_int(client,static_cast<int>(DenyResponse::OK));

        for (const auto &[pkg, procs] : pkg_to_procs) {
            for (const auto &proc : procs) {
                write_int(client, pkg.size() + proc.size() + 1);
                xwrite(client, pkg.data(), pkg.size());
                xwrite(client, "|", 1);
                xwrite(client, proc.data(), proc.size());
            }
        }
    }
    write_int(client, 0);
    close(client);
}

static void update_deny_config() {
    char sql[64];
    sprintf(sql, "REPLACE INTO settings (key,value) VALUES('%s',%d)",
        DB_SETTING_KEYS[DENYLIST_CONFIG], denylist_enforced.load());
    char *err = db_exec(sql);
    db_err(err);
}

void update_sulist_config(bool enable) {
    char sql[64];
    sprintf(sql, "REPLACE INTO settings (key,value) VALUES('%s',%d)",
        DB_SETTING_KEYS[SULIST_CONFIG], enable? 1 : 0);
    char *err = db_exec(sql);
    db_err(err);
}

int enable_deny() {
    if (denylist_enforced) {
        return DenyResponse::OK;
    } else {
        mutex_guard lock(data_lock);

        if (access("/proc/self/ns/mnt", F_OK) != 0) {
            LOGW("The kernel does not support mount namespace\n");
            sulist_enabled = false;
            table_name = "hidelist";
            update_sulist_config(false);
            return DenyResponse::NO_NS;
        }

        if (procfp == nullptr && (procfp = opendir("/proc")) == nullptr)
            goto daemon_error;

        if (sulist_enabled) {
            LOGI("* Enable SuList\n");
        } else {
            LOGI("* Enable MagiskHide\n");
        }

        denylist_enforced = true;

        if (!ensure_data()) {
            denylist_enforced = false;
            goto daemon_error;
        }
        if (!zygisk_enabled && new_daemon_thread(&proc_monitor)){
            // cannot start monitor_proc, return daemon error
            return DenyResponse::ERROR;
        }

        if (sulist_enabled) {
            // Add SystemUI and Settings to sulist because modules might need to modify it
            add_hide_set("com.android.systemui", "com.android.systemui");
            add_hide_set("com.android.settings", "com.android.settings");
            add_hide_set(JAVA_PACKAGE_NAME, JAVA_PACKAGE_NAME);
        }
    }

    update_deny_config();

    return DenyResponse::OK;

    daemon_error:
    sulist_enabled = false;
    table_name = "hidelist";
    update_sulist_config(false);
    return DenyResponse::ERROR;
}

int disable_deny() {
    // sulist mode cannot be turn off without reboot
    if (sulist_enabled)
        return DenyResponse::SULIST_NO_DISABLE;

    if (denylist_enforced) {
        denylist_enforced = false;
        LOGI("* Disable MagiskHide\n");
    }
    if (!zygisk_enabled) {
        pthread_kill(monitor_thread, SIGTERMTHRD);
    }
    update_deny_config();

    return DenyResponse::OK;
}

void initialize_denylist() {
    if (!denylist_enforced) {
        db_settings dbs;
        get_db_settings(dbs, DENYLIST_CONFIG);
        if (dbs[DENYLIST_CONFIG]) {
            // get sulist status before enable denylist
            get_db_settings(dbs, SULIST_CONFIG);
            if (dbs[SULIST_CONFIG]) {
                sulist_enabled = true;
                table_name = "sulist";
            }
            enable_deny();
        }
    }
}

bool is_deny_target(int uid, string_view process, int max_len) {
    mutex_guard lock(data_lock);
    if (!ensure_data())
        return false;

    if (!p_skip_pkg_rescan->test_and_set())
        rescan_apps();

    int app_id = to_app_id(uid);
    int manager_app_id = get_manager();
    string process_name = {process.begin(), process.end()};

    if (app_id == manager_app_id) {
        // allow manager to access Magisk
        return (sulist_enabled)? true : false;
    }

    if (app_id >= 90000) {
        if (auto it = pkg_to_procs.find(ISOLATED_MAGIC); it != pkg_to_procs.end()) {
            for (const auto &s : it->second) {
                if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                    return true;
                if (str_starts(process, s))
                    return true;
            }
        }
        return false;
    } else {
        auto it = app_id_to_pkgs.find(app_id);
        if (it == app_id_to_pkgs.end())
            return false;
        for (const auto &pkg : it->second) {
            if (pkg_to_procs.find(pkg)->second.count(process))
                return true;
        }
        for (const auto &s : it->second) {
            if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                return true;
            if (s == process)
                return true;
        }
    }
    return false;
}

bool is_uid_on_list(int uid) {
    auto it = app_id_to_pkgs.find(uid % 100000);
    // double check
    if (it == app_id_to_pkgs.end())
        return false;
    for (const auto &pkg : it->second) {
        if (pkg_to_procs.find(pkg)->second.size() > 0)
            return true;
    }
    return false;
}
