#include <sys/mount.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <base.hpp>
#include <consts.hpp>
#include <core.hpp>
#include <selinux.hpp>
#include <flags.h>

using namespace std;

int mount_sbin();

static void install_applet(const char *path){
    string s;
    for (int i = 0; applet_names[i]; ++i){
        s = string(path) + "/" + string(applet_names[i]);
        symlink("./magisk", s.data());
    }
    s = string(path) + "/supolicy";
    symlink("./magiskpolicy", s.data());
}

[[noreturn]] static void usage() {
    fprintf(stderr,
R"EOF(Magisk - Multi-purpose Utility

Usage: magisk [applet [arguments]...]
   or: magisk [options]...

Options:
   -c                        print current binary version
   -v                        print running daemon version
   -V                        print running daemon version code
   --list                    list all available applets
   --remove-modules [-n]     remove all modules, reboot if -n is not provided
   --install-module ZIP      install a module zip file

Advanced Options (Internal APIs):
   --daemon                  manually start magisk daemon
   --stop                    remove all magisk changes and stop daemon
   --[init trigger]          callback on init triggers. Valid triggers:
                             post-fs-data, service, boot-complete, zygote-restart
   --unlock-blocks           set BLKROSET flag to OFF for all block devices
   --restorecon              restore selinux context on Magisk files
   --clone-attr SRC DEST     clone permission, owner, and selinux context
   --clone SRC DEST          clone SRC to DEST
   --sqlite SQL              exec SQL commands to Magisk database
   --path                    print Magisk tmpfs mount path
   --preinit-device          resolve a device to store preinit files

Available applets:
)EOF");

    for (int i = 0; applet_names[i]; ++i)
        fprintf(stderr, i ? ", %s" : "    %s", applet_names[i]);
    fprintf(stderr, "\n\n");
    exit(1);
}

int magisk_main(int argc, char *argv[]) {
    if (argc >= 2 && argv[1] == "--auto-selinux"sv) {
        {
            int secontext_fd = xopen("/proc/self/attr/current", O_RDWR);
            if (secontext_fd >= 0 && (
                write(secontext_fd, "u:r:" SEPOL_PROC_DOMAIN ":s0", sizeof("u:r:" SEPOL_PROC_DOMAIN ":s0")) > 0 ||
                // if selinux cannot be changed to u:r:magisk:s0, try u:r:su:s0
                write(secontext_fd, "u:r:su:s0", sizeof("u:r:su:s0")) > 0)) {
                char current_con[128];
                xread(secontext_fd, current_con, sizeof(current_con));
                fprintf(stderr, "SeLinux context: %s\n", current_con);
            }
            close(secontext_fd);
        }
        argc--;
        argv++;
    }
    if (argc < 2)
        usage();
    if (argv[1] == "-c"sv) {
#if MAGISK_DEBUG
        printf(MAGISK_VERSION ":MAGISK:D (" str(MAGISK_VER_CODE) ")\n");
#else
        printf(MAGISK_VERSION ":MAGISK:R (" str(MAGISK_VER_CODE) ")\n");
#endif
        return 0;
    } else if (argv[1] == "-v"sv) {
        int fd = connect_daemon(+RequestCode::CHECK_VERSION);
        string v = read_string(fd);
        printf("%s\n", v.data());
        return 0;
    } else if (argv[1] == "-V"sv) {
        int fd = connect_daemon(+RequestCode::CHECK_VERSION_CODE);
        printf("%d\n", read_int(fd));
        return 0;
    } else if (argv[1] == "--list"sv) {
        for (int i = 0; applet_names[i]; ++i)
            printf("%s\n", applet_names[i]);
        return 0;
    } else if (argv[1] == "--unlock-blocks"sv) {
        unlock_blocks();
        return 0;
    } else if (argv[1] == "--mount-sbin"sv) {
        int ret = mount_sbin();
        return ret;
    } else if (argc > 2 && argv[1] == "--setup-sbin"sv) {
        const char *magisk_tmp = (argc > 3)? argv[3] :  "/sbin";

        if (strcmp(magisk_tmp, "/sbin") == 0) {
            if (mount_sbin() != 0) 
                return -1;
        } else if (tmpfs_mount("magisk", magisk_tmp) != 0) {
            return -1;
        }
        // copy all binaries to sbin
        const char *bins[] = { "magisk32", "magisk64", "magiskpolicy", "stub.apk", nullptr };
        for (int i = 0; bins[i]; i++){
       	    string src = string(argv[2]) + "/" + bins[i];
       	    string dest = string(magisk_tmp) + "/" + bins[i];
       	    if (access(src.data(), F_OK)==0){
       	        cp_afc(src.data(), dest.data());
       	        chmod(dest.data(), 0755);
       	    }
        }
        chdir(magisk_tmp);
        xmkdir(INTLROOT, 0755);
        xmkdir(DEVICEDIR, 0);

#ifdef __LP64__
        symlink("./magisk64", "./magisk");
#else
        symlink("./magisk32", "./magisk");
#endif
        install_applet(magisk_tmp);
        return 0;
    } else if (argv[1] == "--install"sv) {
        if (argc >= 3)
            install_applet(argv[2]);
        else
            install_applet("/sbin");
        return 0;
    } else if (argv[1] == "--restorecon"sv) {
        restorecon();
        return 0;
    } else if (argc >= 4 && argv[1] == "--clone-attr"sv) {
        clone_attr(argv[2], argv[3]);
        return 0;
    } else if (argc >= 4 && argv[1] == "--clone"sv) {
        cp_afc(argv[2], argv[3]);
        return 0;
    } else if (argv[1] == "--daemon"sv) {
        close(connect_daemon(+RequestCode::START_DAEMON, true));
        return 0;
    } else if (argv[1] == "--stop"sv) {
        int fd = connect_daemon(+RequestCode::STOP_DAEMON);
        return read_int(fd);
    } else if (argv[1] == "--post-fs-data"sv) {
        int fd = connect_daemon(+RequestCode::POST_FS_DATA, true);
        struct pollfd pfd = { fd, POLLIN, 0 };
        poll(&pfd, 1, 1000 * POST_FS_DATA_WAIT_TIME);
        return 0;
    } else if (argv[1] == "--service"sv) {
        close(connect_daemon(+RequestCode::LATE_START, true));
        return 0;
    } else if (argv[1] == "--boot-complete"sv) {
        close(connect_daemon(+RequestCode::BOOT_COMPLETE));
        return 0;
    } else if (argv[1] == "--zygote-restart"sv) {
        close(connect_daemon(+RequestCode::ZYGOTE_RESTART));
        return 0;
    } else if (argc >= 3 && argv[1] == "--sqlite"sv) {
        int fd = connect_daemon(+RequestCode::SQLITE_CMD);
        write_string(fd, argv[2]);
        string res;
        for (;;) {
            read_string(fd, res);
            if (res.empty())
                return 0;
            printf("%s\n", res.data());
        }
    } else if (argv[1] == "--remove-modules"sv) {
        int do_reboot;
        if (argc == 3 && argv[2] == "-n"sv) {
            do_reboot = 0;
        } else if (argc == 2) {
            do_reboot = 1;
        } else {
            usage();
        }
        int fd = connect_daemon(+RequestCode::REMOVE_MODULES);
        write_int(fd, do_reboot);
        return read_int(fd);
    } else if (argv[1] == "--path"sv) {
        const char *path = get_magisk_tmp();
        if (path[0] != '\0')  {
            printf("%s\n", path);
            return 0;
        }
        return 1;
    } else if (argc >= 3 && argv[1] == "--install-module"sv) {
        install_module(argv[2]);
    } else if (argv[1] == "--preinit-device"sv) {
        auto name = find_preinit_device();
        LOGD("preinit device: %s\n", name.data());
        if (!name.empty())  {
            printf("%s\n", name.data());
            return 0;
        }
        return 1;
    }
#if 0
    /* Entry point for testing stuffs */
    else if (argv[1] == "--test"sv) {
        rust_test_entry();
        return 0;
    }
#endif
    usage();
}
