#pragma once
#include "Buffer.h"
#include <string>
#include <Windows.h>
#include "HandleGuard.h"

namespace IoUtils
{
    Buffer readFile(const std::wstring& filename);
};

