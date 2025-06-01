#include "IoUtils.h"

Buffer IoUtils::readFile(const std::wstring& filename)
{
    HandleGuard file(CreateFileW(
        filename.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (file.get() == INVALID_HANDLE_VALUE) {
        throw std::exception("Failed to open file");
    }

    DWORD fileSize = GetFileSize(file.get(), nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        throw std::exception("Failed to get file size");
    }

    Buffer buffer(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(file.get(), buffer.data(), fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        throw std::exception("Failed to read file");
    }

    return buffer;
}
