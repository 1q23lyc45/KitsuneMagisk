#include <set>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>

#include <consts.hpp>
#include <base.hpp>
#include <core.hpp>
#include <selinux.hpp>

#include <link.h>

#include "deny.hpp"

using namespace std;

#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/vfs.h>

#define VLOGD(tag, from, to) LOGD("%-8s: %s <- %s\n", tag, to, from)

bool is_rootfs()
{
#define TST_RAMFS_MAGIC    0x858458f6
#define TST_TMPFS_MAGIC    0x01021994
#define TST_OVERLAYFS_MAGIC 0x794c7630
    const char *path= "/";
    struct statfs s;
    statfs(path, &s);

    switch (s.f_type) {
    case TST_TMPFS_MAGIC:
    case TST_RAMFS_MAGIC:
    case TST_OVERLAYFS_MAGIC:
        return true;
    default:
        return false;
    }
}

static bool system_lnk(const char *path){
    char buff[4098];
    ssize_t len = readlink(path, buff, sizeof(buff)-1);
    if (len != -1) {
        return true;
    }
    return false;
}

void recreate_sbin_v2(const char *mirror, bool use_bind_mount) {
    auto dp = xopen_dir(mirror);
    int src = dirfd(dp.get());
    char buf[4096];
    char mbuf[4096];
    for (dirent *entry; (entry = xreaddir(dp.get()));) {
        string sbin_path = "/sbin/"s + entry->d_name;
        struct stat st;
        fstatat(src, entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
        sprintf(buf, "%s/%s", mirror, entry->d_name);
        sprintf(mbuf, "%s/%s", get_magisk_tmp(), entry->d_name);
        if (access(mbuf, F_OK) == 0) continue;
        if (S_ISLNK(st.st_mode)) {
            xreadlinkat(src, entry->d_name, buf, sizeof(buf));
            xsymlink(buf, sbin_path.data());
            VLOGD("create", buf, sbin_path.data());
        } else {
            if (use_bind_mount) {
                auto mode = st.st_mode & 0777;
                // Create dummy
                if (S_ISDIR(st.st_mode))
                    xmkdir(sbin_path.data(), mode);
                else
                    close(xopen(sbin_path.data(), O_CREAT | O_WRONLY | O_CLOEXEC, mode));

                bind_mount_(buf, sbin_path.data());
            } else {
                xsymlink(buf, sbin_path.data());
                VLOGD("create", buf, sbin_path.data());
            }
        }
    }
}

int mount_sbin() {
    if (is_rootfs()){
        if (xmount(nullptr, "/", nullptr, MS_REMOUNT, nullptr) != 0) return -1;
        mkdir("/sbin", 0750);
        rm_rf("/root");
        mkdir("/root", 0750);
        clone_attr("/sbin", "/root");
        link_path("/sbin", "/root");
        if (tmpfs_mount("magisk", "/sbin") != 0) return -1;
        setfilecon("/sbin", "u:object_r:rootfs:s0");
        recreate_sbin_v2("/root", false);
        xmount(nullptr, "/", nullptr, MS_REMOUNT | MS_RDONLY, nullptr);
    } else {
        if (tmpfs_mount("magisk", "/sbin") != 0) return -1;
        setfilecon("/sbin", "u:object_r:rootfs:s0");
        xmkdir("/sbin/" INTLROOT, 0755);
        xmkdir("/sbin/" MIRRDIR, 0755);
        xmkdir("/sbin/" MIRRDIR "/system_root", 0755);
        xmount("/", "/sbin/" MIRRDIR "/system_root", nullptr, MS_BIND, nullptr);
        recreate_sbin_v2("/sbin/" MIRRDIR "/system_root/sbin", true);
        umount2("/sbin/" MIRRDIR "/system_root", MNT_DETACH);
    }
    return 0;
}

static void lazy_unmount(const char* mountpoint) {
    if (umount2(mountpoint, MNT_DETACH) != -1)
        LOGD("denylist: Unmounted (%s)\n", mountpoint);
}

void su_mount();
void mount_mirrors();

void do_mount_magisk(int pid) {
    string MAGISKTMP = get_magisk_tmp();

    if (MAGISKTMP.empty() || switch_mnt_ns(pid))
        return;

    LOGD("sulist: handling PID=[%d]\n", pid);

    xmount(nullptr, "/", nullptr, MS_SLAVE | MS_REC, nullptr);

    if (MAGISKTMP == "/sbin") {
        if (is_rootfs()) {
            tmpfs_mount("magisk", "/sbin");
            setfilecon("/sbin", "u:object_r:rootfs:s0");
            recreate_sbin_v2("/root", false);
        } else {
            mount_sbin();
        }
    } else {
        tmpfs_mount("magisk", MAGISKTMP.data());
    }

    for (auto file : {"magisk32", "magisk64", "magisk", "magiskpolicy"}) {
        auto src = "/proc/self/fd/"s + to_string(magisktmpfs_fd) + "/"s + file;
        auto dest = MAGISKTMP + "/"s + file;
        if (access(src.data(),F_OK) == 0){
            cp_afc(src.data(), dest.data());
        }
    }

    for (int i = 0; applet_names[i]; ++i) {
        string dest = MAGISKTMP + "/" + applet_names[i];
        xsymlink("./magisk", dest.data());
    }
    string dest = MAGISKTMP + "/supolicy";
    xsymlink("./magiskpolicy", dest.data());

    chdir(MAGISKTMP.data());

    xmkdir(INTLROOT, 0755);
    xmount(INTLROOT, INTLROOT, nullptr, MS_BIND, nullptr);

    xmkdir(DEVICEDIR, 0);
    xmkdir(WORKERDIR, 0);

    struct stat st{};
    if (fstatat(magisktmpfs_fd, PREINITDEV, &st, 0) == 0 && S_ISBLK(st.st_mode))
        mknod((MAGISKTMP + "/" PREINITDEV).data(), S_IFBLK, st.st_rdev);

    char path[PATH_MAX];

    // Bind remount module root to clear nosuid
    if (access(SECURE_DIR, F_OK) == 0 || SDK_INT < 24) {
        ssprintf(path, sizeof(path), "%s/" MODULEMNT, get_magisk_tmp());
        xmkdir(SECURE_DIR, 0700);
        xmkdir(MODULEROOT, 0755);
        xmkdir(path, 0755);
        xmount(MODULEROOT, path, nullptr, MS_BIND, nullptr);
        xmount(nullptr, path, nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY, nullptr);
        xmount(nullptr, path, nullptr, MS_PRIVATE, nullptr);
    }

    // Prepare worker
    ssprintf(path, sizeof(path), "%s/" WORKERDIR, get_magisk_tmp());
    xmount("worker", path, "tmpfs", 0, "mode=755");
    xmount(nullptr, path, nullptr, MS_PRIVATE, nullptr);

    chdir("/");

    logging_muted = true;
    su_mount();

    umount2(INTLROOT, MNT_DETACH);
}

void mount_magisk_to_pid(int pid) {
    if (fork_dont_care() == 0) {
        do_mount_magisk(pid);
        // send resume signal
        kill(pid, SIGCONT);
        _exit(0);
    }
}

void revert_daemon(int pid, int client) {
    if (fork_dont_care() == 0) {
        revert_unmount(pid);
        if (client >= 0) {
            write_int(client, DenyResponse::OK);
        } else if (client == -1) {
            // send resume signal
            kill(pid, SIGCONT);
        }
        _exit(0);
    }
}

void revert_unmount(int pid) {
    if (pid > 0) {
        if (switch_mnt_ns(pid))
            return;
        LOGD("denylist: handling PID=[%d]\n", pid);
    }
    set<string> targets;

    // Unmount dummy skeletons and MAGISKTMP
    // since mirror nodes are always mounted under skeleton, we don't have to specifically unmount

    // magisk tmpfs
    for (auto &info: parse_mount_info("self")) {
        if (info.source == "magisk")
            targets.insert(info.target);
    }
    for (auto &s : reversed(targets))
        lazy_unmount(s.data());
    targets.clear();

    // tmpfs mount
    for (auto &info: parse_mount_info("self")) {
        if (info.source == "worker")
            targets.insert(info.target);
    }
    for (auto &s : reversed(targets))
        lazy_unmount(s.data());
    targets.clear();

    // module bind mount
    for (auto &info: parse_mount_info("self")) {
        if (info.root.starts_with("/adb/modules") ||
            info.target.starts_with("/data/adb/modules"))
            targets.insert(info.target);
    }
    for (auto &s : reversed(targets))
        lazy_unmount(s.data());
    targets.clear();

    // Unmount early-mount.d files
    for (auto &info: parse_mount_info("self")) {
        if (info.source == EARLYMNTNAME) { // bind mount from early-mount
            lazy_unmount(info.target.data());
        }
    }
}
