// memory.hpp
#pragma once
#include <Windows.h>
#include <string>
#include <string_view>
#include <fstream>
#include <mutex>
#include <vector>
#include <sstream>
#include "vmmdll.h"
#include "util.hpp"

namespace memory
{
    namespace detail
    {
        extern VMM_HANDLE hVMM;
        extern DWORD process_id;
        extern HANDLE process_handle;
        extern ULONG64 process_base_address;
        extern DWORD process_size;
    }

    bool init(DWORD pid);
    bool get_process_base_address(DWORD pid, ULONG64& base_address, DWORD& image_size);

    __forceinline bool vmmdll_read(uint64_t address, void* buffer, size_t size) {
        return VMMDLL_MemRead(detail::hVMM, detail::process_id, address, static_cast<PBYTE>(buffer), size);
    }

    template<class T>
    __forceinline T read(uintptr_t address)
    {
        T buffer;
        vmmdll_read(address, &buffer, sizeof(T));
        return buffer;
    }

    bool read_buffer(uintptr_t address, void* buffer, size_t size);
}