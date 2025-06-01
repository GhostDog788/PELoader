#pragma once

#include <windows.h>
#include <memory>

struct HandleDeleter {
    void operator()(HANDLE handle) const {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

using HandleGuard = std::unique_ptr<std::remove_pointer<HANDLE>::type, HandleDeleter>;
