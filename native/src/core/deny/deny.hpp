#pragma once

#include <pthread.h>
#include <string_view>
#include <functional>
#include <map>
#include <atomic>

#include <core.hpp>

#define ISOLATED_MAGIC "isolated"

#define SIGTERMTHRD SIGUSR1

namespace DenyRequest {
enum : int {
    ENFORCE,
    DISABLE,
    ADD,
    REMOVE,
    LIST,
    STATUS,
    SULIST_STATUS,
    ENFORCE_SULIST,
    DISABLE_SULIST,

    END
};
}

namespace DenyResponse {
enum : int {
    OK,
    ENFORCED,
    NOT_ENFORCED,
    ITEM_EXIST,
    ITEM_NOT_EXIST,
    INVALID_PKG,
    NO_NS,
    ERROR,
    SULIST_ENFORCED,
    SULIST_NOT_ENFORCED,
    SULIST_NO_DISABLE,

    END
};
}

// CLI entries
int enable_deny();
int disable_deny();
int add_list(int client);
int rm_list(int client);
void ls_list(int client);

// Misc
int new_daemon_thread(void(*entry)());
bool is_uid_on_list(int uid);
void rescan_apps();
