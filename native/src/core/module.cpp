#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <map>
#include <utility>

#include <base.hpp>
#include <consts.hpp>
#include <core.hpp>
#include <selinux.hpp>

#include "node.hpp"

using namespace std;

#define VLOGD(tag, from, to) LOGD("%-8s: %s <- %s\n", tag, to, from)

static int bind_mount(const char *reason, const char *from, const char *to) {
    VLOGD(reason, from, to);
    return xmount(from, to, nullptr, MS_BIND | MS_REC, nullptr);
}

/*************************
 * Node Tree Construction
 *************************/

tmpfs_node::tmpfs_node(node_entry *node) : dir_node(node, this) {
    if (!replace()) {
        if (auto dir = open_dir(node_path().data())) {
            set_exist(true);
            for (dirent *entry; (entry = xreaddir(dir.get()));) {
                // create a dummy inter_node to upgrade later
                emplace<inter_node>(entry->d_name, entry);
            }
        }
    }

    for (auto it = children.begin(); it != children.end(); ++it) {
        // Upgrade resting inter_node children to tmpfs_node
        if (isa<inter_node>(it->second))
            it = upgrade<tmpfs_node>(it);
    }
}

bool dir_node::prepare() {
    // If direct replace or not exist, mount ourselves as tmpfs
    bool upgrade_to_tmpfs = replace() || !exist();

    for (auto it = children.begin(); it != children.end();) {
        // We also need to upgrade to tmpfs node if any child:
        // - Target does not exist
        // - Source or target is a symlink (since we cannot bind mount symlink)or whiteout
        bool cannot_mnt;
        if (struct stat st{}; lstat(it->second->node_path().data(), &st) != 0) {
            // if it's a whiteout, we don't care if the target doesn't exist
            cannot_mnt = !it->second->is_wht();
        } else {
            it->second->set_exist(true);
            cannot_mnt = it->second->is_lnk() || S_ISLNK(st.st_mode) || it->second->is_wht();
        }

        if (cannot_mnt) {
            if (_node_type > type_id<tmpfs_node>()) {
                // Upgrade will fail, remove the unsupported child node
                LOGW("Unable to add: %s, skipped\n", it->second->node_path().data());
                delete it->second;
                it = children.erase(it);
                continue;
            }
            upgrade_to_tmpfs = true;
        }
        if (auto dn = dyn_cast<dir_node>(it->second)) {
            if (replace()) {
                // Propagate skip mirror state to all children
                dn->set_replace(true);
            }
            if (dn->prepare()) {
                // Upgrade child to tmpfs
                it = upgrade<tmpfs_node>(it);
            }
        }
        ++it;
    }
    return upgrade_to_tmpfs;
}

void dir_node::collect_module_files(const char *module, int dfd) {
    auto dir = xopen_dir(xopenat(dfd, name().data(), O_RDONLY | O_CLOEXEC));
    if (!dir)
        return;

    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        if (entry->d_name == ".replace"sv) {
            set_replace(true);
            continue;
        }

        if (entry->d_type == DT_DIR) {
            inter_node *node;
            if (auto it = children.find(entry->d_name); it == children.end()) {
                node = emplace<inter_node>(entry->d_name, entry->d_name);
            } else {
                node = dyn_cast<inter_node>(it->second);
            }
            if (node) {
                node->collect_module_files(module, dirfd(dir.get()));
            }
        } else {
            if (struct stat st{}; fstatat(dirfd(dir.get()), entry->d_name, &st,
                                          AT_SYMLINK_NOFOLLOW) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == 0) {
                // if the file is a whiteout, mark it as such
                entry->d_type = DT_WHT;
            }
            emplace<module_node>(entry->d_name, module, entry);
        }
    }
}

/************************
 * Mount Implementations
 ************************/

void node_entry::create_and_mount(const char *reason, const string &src, bool ro) {
    const string dest = isa<tmpfs_node>(parent()) ? worker_path() : node_path();
    if (is_lnk()) {
        VLOGD("cp_link", src.data(), dest.data());
        cp_afc(src.data(), dest.data());
    } else {
        if (is_dir())
            xmkdir(dest.data(), 0);
        else if (is_reg())
            close(xopen(dest.data(), O_RDONLY | O_CREAT | O_CLOEXEC, 0));
        else
            return;
        bind_mount(reason, src.data(), dest.data());
        if (ro) {
            xmount(nullptr, dest.data(), nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY, nullptr);
        }
    }
}

void module_node::mount() {
    std::string path = module;
    if (!string(module).ends_with("/root"))
    	path += parent()->root()->prefix;
    path += node_path();
    string mnt_src = module_mnt + path;
    {
        string src = MODULEROOT "/" + path;
        if (is_wht() && !is_lnk()) {
            VLOGD("delete", "null", node_path().data());
            return;
        }
        if (exist()) clone_attr(node_path().data(), src.data());
    }
    if (isa<tmpfs_node>(parent())) {
        create_and_mount("module", mnt_src);
    } else {
        bind_mount("module", mnt_src.data(), node_path().data());
    }
}

static vector<string> tmpfs_mnt;

void tmpfs_node::mount() {
    if (!is_dir()) {
        create_and_mount("mirror", node_path());
        return;
    }
    if (!isa<tmpfs_node>(parent())) {
        auto worker_dir = worker_path();
        mkdirs(worker_dir.data(), 0);
        bind_mount("tmpfs", worker_dir.data(), worker_dir.data());
        clone_attr(exist() ? node_path().data() : parent()->node_path().data(), worker_dir.data());
        dir_node::mount();
        VLOGD(replace() ? "replace" : "move", worker_dir.data(), node_path().data());
        if (!xmount(worker_dir.data(), node_path().data(), nullptr, MS_MOVE, nullptr))
            tmpfs_mnt.push_back(node_path());
    } else {
        const string dest = worker_path();
        // We don't need another layer of tmpfs if parent is tmpfs
        mkdir(dest.data(), 0);
        clone_attr(exist() ? node_path().data() : parent()->worker_path().data(), dest.data());
        dir_node::mount();
    }
}

/****************
 * Magisk Stuffs
 ****************/

class magisk_node : public node_entry {
public:
    explicit magisk_node(const char *name) : node_entry(name, DT_REG, this) {}

    void mount() override {
        const string src = get_magisk_tmp() + "/"s + name();
        if (access(src.data(), F_OK))
            return;

        const string dir_name = isa<tmpfs_node>(parent()) ? parent()->worker_path() : parent()->node_path();
        if (name() == "supolicy") {
            string dest = dir_name + "/" + name();
            VLOGD("create", "./magiskpolicy", dest.data());
            xsymlink("./magiskpolicy", dest.data());
            return; 
        }
        if (name() != "magisk" && name() != "magiskpolicy") {
            string dest = dir_name + "/" + name();
            VLOGD("create", "./magisk", dest.data());
            xsymlink("./magisk", dest.data());
            return;
        }
        create_and_mount("magisk", src, true);
    }
};

class zygisk_node : public node_entry {
public:
    explicit zygisk_node(const char *name, bool is64bit) : node_entry(name, DT_REG, this),
                                                           is64bit(is64bit) {}

    void mount() override {
        const string src = get_magisk_tmp() + "/magisk"s + (is64bit ? "64" : "32");
        create_and_mount("zygisk", src, true);
    }

private:
    bool is64bit;
};

static void inject_magisk_bins(dir_node *system) {
    auto bin = system->get_child<inter_node>("bin");
    if (!bin) {
        bin = new inter_node("bin");
        system->insert(bin);
    }

    const char *bins[] = { "magisk", "magiskpolicy", "supolicy", nullptr };

    for (int i = 0; bins[i]; ++i)
        bin->insert(new magisk_node(bins[i]));

    for (int i = 0; applet_names[i]; ++i)
        bin->insert(new magisk_node(applet_names[i]));
}

vector<module_info> *module_list;

static void load_modules(bool su_mount) {
    node_entry::module_mnt =  get_magisk_tmp() + "/"s MODULEMNT "/";

    auto root = make_unique<root_node>("");
    auto system = new root_node("system");
    root->insert(system);

    // Additional supported partitions without /system/part symlink
    const char *part_extra[] = {
        "/odm",
        "/vendor_dlkm",
        "/odm_dlkm",
        "/prism",
        "/optics",
        "/oem",
        "/apex",

        // my_* partitions
        "/my_custom",
        "/my_engineering",
        "/my_heytap",
        "/my_manifest",
        "/my_preload",
        "/my_product",
        "/my_region",
        "/my_stock",
        "/my_version",
        "/my_company",
        "/my_carrier",
        "/my_bigball"
    };

    map<string, dir_node *> part_map;
    part_map.insert(make_pair(string("/system"), system));

    for (const char *part : part_extra) {
        struct stat st{};
        if (lstat(part, &st) == 0 && S_ISDIR(st.st_mode)) {
            auto child_node = new root_node(part + 1);
            root->insert(child_node);
            part_map.insert(make_pair(string(part), child_node));
        }
    }

    char buf[4096];
    LOGI("* Loading modules\n");
    for (auto &m : *module_list) {
        const char *module = m.name.data();
        char *b = buf + ssprintf(buf, sizeof(buf), "%s/" MODULEMNT "/%s/", get_magisk_tmp(), module);

        if (su_mount) goto mount_systemless;

        // Read props
        strcpy(b, "system.prop");
        if (access(buf, F_OK) == 0) {
            LOGI("%s: loading [system.prop]\n", module);
            // Do NOT go through property service as it could cause boot lock
            load_prop_file(buf, true);
        }

        mount_systemless:
        // Check whether skip mounting
        strcpy(b, "skip_mount");
        if (access(buf, F_OK) == 0)
            continue;

        // Double check whether the system folder exists
        strcpy(b, "system");
        if (access(buf, F_OK) != 0)
            continue;

        LOGI("%s: loading mount files\n", module);
        b[-1] = '\0';
        int fd = xopen(buf, O_RDONLY | O_CLOEXEC);
        system->collect_module_files(module, fd);
        close(fd);
    }

    // extract /system/part to /part
    if (!root->is_empty()) {
        // Handle special read-only partitions
        for (const char *part : { "/vendor", "/product", "/system_ext" }) {
            struct stat st{};
            if (lstat(part, &st) == 0 && S_ISDIR(st.st_mode)) {
                if (auto old = system->extract(part + 1)) {
                    auto new_node = new root_node(old);
                    root->insert(new_node);
                    part_map.insert(make_pair(string(part), new_node));
                } else {
                    // Create new empty root_node
                    auto child_node = new root_node(part + 1);
                    root->insert(child_node);
                    part_map.insert(make_pair(string(part), child_node));
                }
            }
        }
    }

    // Load new mount API
    for (auto &m : *module_list) {
        const char *module = m.name.data();
        char *b = buf + ssprintf(buf, sizeof(buf), "%s/" MODULEMNT "/%s/", get_magisk_tmp(), module);

        // Check whether skip mounting
        strcpy(b, "skip_mount");
        if (access(buf, F_OK) == 0)
            continue;

        // Double check whether the root folder exists
        // new api to mount more partitions: MODDIR/root
        strcpy(b, "root");
        if (access(buf, F_OK) != 0)
            continue;

        LOGI("%s: loading new mount files api\n", module);
        m.buf = m.name + "/root";
        module = m.buf.data();

        int fd = xopen(buf, O_RDONLY | O_CLOEXEC);
        // basic partitions
        for (const char *part : { "/system", "/vendor", "/product", "/system_ext" }) {
            if (faccessat(fd, part + 1, F_OK, 0) != 0)
                continue;
            auto it = part_map.find(part);
            if (it != part_map.end())
                it->second->collect_module_files(module, fd);
        }
        // more partitions
        for (const char *part : part_extra) {
            if (faccessat(fd, part + 1, F_OK, 0) != 0)
                continue;
            if (auto it = part_map.find(part); it != part_map.end()) {
                it->second->collect_module_files(module, fd);
            }
        }
        close(fd);
    }

    // Remove partitions which are not needed by modules
    for (auto it = part_map.begin(); it != part_map.end(); it++) {
        if (it->second->is_empty()) {
            if (auto old = root->extract(it->first.data() + 1)) delete old;
        }
    }

    if (!root->is_empty()) {
        root->prepare();
        root->mount();
    }

    ssprintf(buf, sizeof(buf), "%s/" WORKERDIR, get_magisk_tmp());
    xmount(nullptr, buf, nullptr, MS_REMOUNT | MS_RDONLY, nullptr);

    for (auto &s : tmpfs_mnt) {
        xmount(nullptr, s.data(), nullptr, MS_SHARED, nullptr);
        xmount(nullptr, s.data(), nullptr, MS_REMOUNT | MS_RDONLY, nullptr);
    }
    tmpfs_mnt.clear();
}

void load_modules() {
    load_modules(false);
}

static int mount_su() {
    node_entry::module_mnt =  get_magisk_tmp() + "/"s MODULEMNT "/";
    char buf[4096];
    ssprintf(buf, sizeof(buf), "%s/" WORKERDIR, get_magisk_tmp());
    if (xmount("magisk", buf, "tmpfs", 0, "mode=755"))
        return -1;
    xmount(nullptr, buf, nullptr, MS_PRIVATE, nullptr);

    auto root = make_unique<root_node>("");
    auto system = new root_node("system");
    root->insert(system);

    // Need to inject our binaries into PATH
    inject_magisk_bins(system);

    if (!root->is_empty()) {
        root->prepare();
        root->mount();
    }

    struct stat st_src{}, st_dest{};
    stat(buf, &st_src);
    stat("/system/bin", &st_dest);
    umount2(buf, MNT_DETACH);

    int fd = (st_src.st_dev == st_dest.st_dev)?
        xopen("/system/bin", O_PATH | O_CLOEXEC) : -1;

    ssprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd);
    xmount(nullptr, buf, nullptr, MS_REMOUNT | MS_RDONLY, nullptr);

    tmpfs_mnt.clear();

    return fd;
}

int su_bin_fd = -1;

void enable_mount_su() {
    if (su_bin_fd < 0) {
        LOGI("* Mount MagiskSU\n");
        su_bin_fd = mount_su();

        char buf[128];
        ssprintf(buf, sizeof(buf), "/proc/self/fd/%d", su_bin_fd);
        xmount(nullptr, buf, nullptr, MS_SHARED, nullptr);
    }
}

void disable_unmount_su() {
    if (su_bin_fd >= 0) {
        LOGI("* Unmount MagiskSU\n");
        char buf[128];
        ssprintf(buf, sizeof(buf), "/proc/self/fd/%d", su_bin_fd);
        umount2(buf, MNT_DETACH);
        close(su_bin_fd);
        su_bin_fd = -1;
    }
}

void su_mount() {
    load_modules(true);
    close(mount_su());
}


/************************
 * Filesystem operations
 ************************/

static void prepare_modules() {
    // Upgrade modules
    if (auto dir = open_dir(MODULEUPGRADE); dir) {
        int ufd = dirfd(dir.get());
        int mfd = xopen(MODULEROOT, O_RDONLY | O_CLOEXEC);
        for (dirent *entry; (entry = xreaddir(dir.get()));) {
            if (entry->d_type == DT_DIR) {
                // Cleanup old module if exists
                if (faccessat(mfd, entry->d_name, F_OK, 0) == 0) {
                    int modfd = xopenat(mfd, entry->d_name, O_RDONLY | O_CLOEXEC);
                    if (faccessat(modfd, "disable", F_OK, 0) == 0) {
                        auto disable = entry->d_name + "/disable"s;
                        close(xopenat(ufd, disable.data(), O_RDONLY | O_CREAT | O_CLOEXEC, 0));
                    }
                    frm_rf(modfd);
                    unlinkat(mfd, entry->d_name, AT_REMOVEDIR);
                }
                LOGI("Upgrade / New module: %s\n", entry->d_name);
                renameat(ufd, entry->d_name, mfd, entry->d_name);
            }
        }
        close(mfd);
        rm_rf(MODULEUPGRADE);
    }
}

template<typename Func>
static void foreach_module(Func fn) {
    auto dir = open_dir(MODULEROOT);
    if (!dir)
        return;

    int dfd = dirfd(dir.get());
    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        if (entry->d_type == DT_DIR && entry->d_name != ".core"sv) {
            int modfd = xopenat(dfd, entry->d_name, O_RDONLY | O_CLOEXEC);
            fn(dfd, entry, modfd);
            close(modfd);
        }
    }
}

static void collect_modules(bool open_zygisk) {
    foreach_module([=](int dfd, dirent *entry, int modfd) {
        if (faccessat(modfd, "remove", F_OK, 0) == 0) {
            LOGI("%s: remove\n", entry->d_name);
            auto uninstaller = MODULEROOT + "/"s + entry->d_name + "/uninstall.sh";
            if (access(uninstaller.data(), F_OK) == 0)
                exec_script(uninstaller.data());
            frm_rf(xdup(modfd));
            unlinkat(dfd, entry->d_name, AT_REMOVEDIR);
            return;
        }
        unlinkat(modfd, "update", 0);
        if (faccessat(modfd, "disable", F_OK, 0) == 0)
            return;

        module_info info;
        if (zygisk_enabled) {
            // Riru and its modules are not compatible with zygisk
            if (entry->d_name == "riru-core"sv || faccessat(modfd, "riru", F_OK, 0) == 0) {
                LOGI("%s: ignore\n", entry->d_name);
                return;
            }
            if (open_zygisk) {
#if defined(__arm__)
                info.z32 = openat(modfd, "zygisk/armeabi-v7a.so", O_RDONLY | O_CLOEXEC);
#elif defined(__aarch64__)
                info.z32 = openat(modfd, "zygisk/armeabi-v7a.so", O_RDONLY | O_CLOEXEC);
                info.z64 = openat(modfd, "zygisk/arm64-v8a.so", O_RDONLY | O_CLOEXEC);
#elif defined(__i386__)
                info.z32 = openat(modfd, "zygisk/x86.so", O_RDONLY | O_CLOEXEC);
#elif defined(__x86_64__)
                info.z32 = openat(modfd, "zygisk/x86.so", O_RDONLY | O_CLOEXEC);
                info.z64 = openat(modfd, "zygisk/x86_64.so", O_RDONLY | O_CLOEXEC);
#else
#error Unsupported ABI
#endif
                unlinkat(modfd, "zygisk/unloaded", 0);
            }
        } else {
            // Ignore zygisk modules when zygisk is not enabled
            if (faccessat(modfd, "zygisk", F_OK, 0) == 0) {
                LOGI("%s: ignore\n", entry->d_name);
                return;
            }
        }
        if (!open_zygisk) { // Load sepolicy.rule if possible
            string module_mnt_dir = string(get_magisk_tmp()) + "/" MODULEMNT "/" + entry->d_name;
            string module_rule = string(get_magisk_tmp()) + "/" PREINITMIRR "/" + entry->d_name;
            string module_rulefile = module_mnt_dir + "/sepolicy.rule";
            if (access(module_rulefile.data(), F_OK) == 0){
                struct stat st_modulemnt;
                struct stat st_modulerule;
                // if rule file is not found
                if (access(string(module_rule + "/sepolicy.rule").data(), F_OK) != 0) {
                    LOGI("%s: applying [sepolicy.rule]\n", entry->d_name);
                    char MAGISKPOLICY[PATH_MAX];
                    sprintf(MAGISKPOLICY, "%s/magiskpolicy", get_magisk_tmp());
                    auto ret = exec_command_sync(MAGISKPOLICY, "--live", "--apply", module_rulefile.data());
                    if (ret != 0) LOGW("%s: failed to apply [sepolicy.rule]\n", entry->d_name);
                }
                if (stat(module_mnt_dir.data(), &st_modulemnt) == 0 &&
                    (stat(module_rule.data(), &st_modulerule) != 0 ||
                     st_modulemnt.st_dev != st_modulerule.st_dev ||
                     st_modulemnt.st_ino != st_modulerule.st_ino)) {
                         // refresh rule file
                         LOGI("%s: refresh [sepolicy.rule]\n", entry->d_name);
                         rm_rf(module_rule.data());
                         mkdirs(module_rule.data(), 0755);
                         cp_afc(module_rulefile.data(), string(module_rule + "/sepolicy.rule").data());
                }
            }
        }
        info.name = entry->d_name;
        module_list->push_back(info);
    });
    if (zygisk_enabled) {
        bool use_memfd = true;
        auto convert_to_memfd = [&](int fd) -> int {
            if (fd < 0)
                return -1;
            if (use_memfd) {
                int memfd = syscall(__NR_memfd_create, "jit-zygisk-cache", MFD_CLOEXEC);
                if (memfd >= 0) {
                    xsendfile(memfd, fd, nullptr, INT_MAX);
                    close(fd);
                    return memfd;
                } else {
                    // memfd_create failed, just use what we had
                    use_memfd = false;
                }
            }
            return fd;
        };
        std::for_each(module_list->begin(), module_list->end(), [&](module_info &info) {
            info.z32 = convert_to_memfd(info.z32);
#if defined(__LP64__)
            info.z64 = convert_to_memfd(info.z64);
#endif
        });
    }
}

void handle_modules() {
    prepare_modules();
    collect_modules(false);
    exec_module_scripts("post-fs-data");

    // Recollect modules (module scripts could remove itself)
    module_list->clear();
    collect_modules(true);
}

static int check_rules_dir(char *buf, size_t sz) {
    int off = ssprintf(buf, sz, "%s/" PREINITMIRR, get_magisk_tmp());
    struct stat st1{};
    struct stat st2{};
    if (xstat(buf, &st1) < 0 || xstat(MODULEROOT, &st2) < 0)
        return 0;
    if (st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino)
        return 0;
    return off;
}

void disable_modules() {
    char buf[4096];
    int off = check_rules_dir(buf, sizeof(buf));
    foreach_module([&](int, dirent *entry, int modfd) {
        close(xopenat(modfd, "disable", O_RDONLY | O_CREAT | O_CLOEXEC, 0));
        if (off) {
            ssprintf(buf + off, sizeof(buf) - off, "/%s/sepolicy.rule", entry->d_name);
            unlink(buf);
            ssprintf(buf + off, sizeof(buf) - off, "/%s/early-mount", entry->d_name);
            rm_rf(buf);
        }
    });
}

void remove_modules() {
    char buf[4096];
    int off = check_rules_dir(buf, sizeof(buf));
    foreach_module([&](int, dirent *entry, int) {
        auto uninstaller = MODULEROOT + "/"s + entry->d_name + "/uninstall.sh";
        if (access(uninstaller.data(), F_OK) == 0)
            exec_script(uninstaller.data());
        if (off) {
            ssprintf(buf + off, sizeof(buf) - off, "/%s/sepolicy.rule", entry->d_name);
            unlink(buf);
            ssprintf(buf + off, sizeof(buf) - off, "/%s/early-mount", entry->d_name);
            rm_rf(buf);
        }
    });
    rm_rf(MODULEROOT);
}

void exec_module_scripts(const char *stage) {
    vector<string_view> module_names;
    std::transform(module_list->begin(), module_list->end(), std::back_inserter(module_names),
        [](const module_info &info) -> string_view { return info.name; });
    exec_module_scripts(stage, module_names);
}
