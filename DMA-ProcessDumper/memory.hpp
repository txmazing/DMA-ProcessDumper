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
		inline VMM_HANDLE hVMM;
		inline std::string process_name;
		inline uint32_t process_id;
		inline HANDLE process_handle;
		inline ULONG64 process_base_address;
		inline DWORD process_size;
	}

	bool init(const std::string process_name);

	__forceinline bool vmmdll_read(uint64_t address, void* buffer, size_t size) {
		if (VMMDLL_MemRead(detail::hVMM, (DWORD)detail::process_id, (ULONG64)address, (PBYTE)buffer, size)) {
			return true;
		}

		return false;
	}

	template<class T> __forceinline T read(uintptr_t address)
	{
		T buffer;
		vmmdll_read(address, &buffer, sizeof(T));
		return buffer;
	}

    __forceinline bool read_buffer(uintptr_t address, void* buffer, size_t size)
    {
        const size_t PAGE_SIZE = 0x1000;
        size_t bytesRead = 0;
        BYTE* pBuffer = (BYTE*)buffer;

        while (bytesRead < size) {
            size_t remainingBytes = size - bytesRead;
            size_t bytesToRead = (remainingBytes < PAGE_SIZE) ? remainingBytes : PAGE_SIZE;

            PVMMDLL_MAP_VADEX pVadEx = NULL;

            if (VMMDLL_Map_GetVadEx(detail::hVMM, detail::process_id, (address + bytesRead) / PAGE_SIZE, 1, &pVadEx)) {
                if (pVadEx && pVadEx->cMap > 0) {
                    // Überprüfen Sie hier die VAD-Informationen
                    // Beachten Sie, dass wir die genaue Struktur von VMMDLL_MAP_VADEXENTRY nicht kennen,
                    // daher müssen wir vorsichtig sein, wie wir auf die Eigenschaften zugreifen
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
                // Wenn die Seite nicht zugänglich ist oder keine VAD-Informationen vorhanden sind, überspringen wir sie einfach
                VMMDLL_MemFree(pVadEx);
            }
            else {
                // Wenn wir keine VAD-Informationen erhalten können, versuchen wir trotzdem zu lesen
                DWORD pageRead;
                if (!VMMDLL_MemReadEx(detail::hVMM, detail::process_id,
                    address + bytesRead,
                    pBuffer + bytesRead,
                    bytesToRead, &pageRead, VMMDLL_FLAG_NOCACHE)) {
                    // Wenn das Lesen fehlschlägt, füllen wir mit Nullen
                    memset(pBuffer + bytesRead, 0, bytesToRead);
                }
            }

            bytesRead += bytesToRead;
        }

        return true;
    }

	inline uint32_t get_process_id(const std::string process_name)
	{
		DWORD dwPID;
		bool result = VMMDLL_PidGetFromName(detail::hVMM, const_cast<char*>(process_name.c_str()), &dwPID);

		return dwPID;
	}

	inline bool get_process_base_address(const std::string process_name, const uint32_t& process_id)
	{
		DWORD dwPID;
		PVMMDLL_MAP_MODULEENTRY pModuleEntryExplorer;
		bool result = VMMDLL_Map_GetModuleFromNameU(detail::hVMM, process_id, const_cast<char*>(process_name.c_str()), &pModuleEntryExplorer, NULL);

		if (result) {
			detail::process_size = pModuleEntryExplorer->cbImageSize;
			detail::process_base_address = pModuleEntryExplorer->vaBase;
			
			return true;
		}

		return false;
	}
}