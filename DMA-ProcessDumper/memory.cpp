// memory.cpp
#include "memory.hpp"

namespace memory::detail
{
    VMM_HANDLE hVMM;
    DWORD process_id;
    HANDLE process_handle;
    ULONG64 process_base_address;
    DWORD process_size;
}

bool memory::init(DWORD pid)
{
    LPSTR args[] = { (LPSTR)"", (LPSTR)"-device", (LPSTR)"fpga" };
    detail::hVMM = VMMDLL_Initialize(3, args);
    if (!detail::hVMM) {
        printf("[!] Failed to initialize memory process file system in call to vmm.dll!VMMDLL_Initialize (Error: %d)\n", GetLastError());
        return false;
    }
    printf("[>] Init handle VMM success\n");

    detail::process_id = pid;
    printf("[+] Process id: %d\n", detail::process_id);

    if (!get_process_base_address(pid, detail::process_base_address, detail::process_size))
    {
        printf("[!] Failed to get base address/size of process with PID %d (Error: %d)\n", pid, GetLastError());
        return false;
    }
    printf("[+] Base address: 0x%llX\n", detail::process_base_address);
    printf("[+] Image size: 0x%X\n", detail::process_size);
    return true;
}

bool memory::get_process_base_address(DWORD pid, ULONG64& base_address, DWORD& image_size)
{
    VMMDLL_PROCESS_INFORMATION info = { 0 };
    info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    SIZE_T cb = sizeof(info);
    if (!VMMDLL_ProcessGetInformation(detail::hVMM, pid, &info, &cb)) {
        return false;
    }

    PVMMDLL_MAP_MODULEENTRY pModule = NULL;
    if (!VMMDLL_Map_GetModuleFromName(detail::hVMM, pid, NULL, &pModule, NULL)) {
        return false;
    }

    if (pModule) {
        base_address = pModule->vaBase;
        image_size = pModule->cbImageSize;
        VMMDLL_MemFree(pModule);
        return true;
    }

    return false;
}

bool memory::read_buffer(uintptr_t address, void* buffer, size_t size)
{
    const size_t PAGE_SIZE = 0x1000;
    size_t bytesRead = 0;
    BYTE* pBuffer = static_cast<BYTE*>(buffer);

    while (bytesRead < size) {
        size_t remainingBytes = size - bytesRead;
        size_t bytesToRead = (remainingBytes < PAGE_SIZE) ? remainingBytes : PAGE_SIZE;
        PVMMDLL_MAP_VADEX pVadEx = NULL;

        if (VMMDLL_Map_GetVadEx(detail::hVMM, detail::process_id, (address + bytesRead) / PAGE_SIZE, 1, &pVadEx)) {
            if (pVadEx && pVadEx->cMap > 0) {
                DWORD pageRead;
                if (!VMMDLL_MemReadEx(detail::hVMM, detail::process_id,
                    address + bytesRead,
                    pBuffer + bytesRead,
                    bytesToRead, &pageRead, VMMDLL_FLAG_NOCACHE)) {
                    VMMDLL_MemFree(pVadEx);
                    return false;
                }
                if (pageRead != bytesToRead) {
                    VMMDLL_MemFree(pVadEx);
                    return false;
                }
            }
            VMMDLL_MemFree(pVadEx);
        }
        else {
            DWORD pageRead;
            if (!VMMDLL_MemReadEx(detail::hVMM, detail::process_id,
                address + bytesRead,
                pBuffer + bytesRead,
                bytesToRead, &pageRead, VMMDLL_FLAG_NOCACHE)) {
                memset(pBuffer + bytesRead, 0, bytesToRead);
            }
        }
        bytesRead += bytesToRead;
    }
    return true;
}