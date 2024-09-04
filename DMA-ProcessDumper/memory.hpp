#pragma once
#include <Windows.h>
#include <string>
#include <string_view>
#include <fstream>
#include <mutex>
#include <vector>

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
		// Byfron read
		// Credits to https://www.unknowncheats.me/forum/3484102-post9127.html

		uint64_t read;
		MEMORY_BASIC_INFORMATION pbi;
		auto chunks_num = size / 0x1000;
		auto staraddr = (__int64)address;
		auto staraddrbuf = (__int64)buffer;

		for (size_t i = 0; i < chunks_num; i++)
		{
			auto remotepage = staraddr + 0x1000 * i;
			auto localpage = staraddrbuf + 0x1000 * i;
			VirtualQueryEx(detail::process_handle, (void*)address, &pbi, sizeof(pbi));
			if (pbi.Protect != PAGE_NOACCESS)
			{
				vmmdll_read(remotepage, (void*)localpage, 0x1000);
			}
		}
		return 1;

		//return vmmdll_read(address, buffer, size);
	}

	inline uint32_t get_process_id(const std::string process_name)
	{
		/*DWORD dwPID;
		bool result = VMMDLL_PidGetFromName(detail::hVMM, const_cast<char*>(process_name.c_str()), &dwPID);

		return dwPID;*/

		SIZE_T numPIDs = 0;
		std::vector<DWORD> pids;
		std::vector<DWORD> matching_pids;

		if (!VMMDLL_PidList(detail::hVMM, nullptr, &numPIDs)) {
			throw std::runtime_error("Error getting PID count");
		}

		pids.resize(numPIDs);

		if (!VMMDLL_PidList(detail::hVMM, pids.data(), &numPIDs)) {
			throw std::runtime_error("Error getting PID list");
		}

		for (const auto& pid : pids) {
			VMMDLL_PROCESS_INFORMATION info = { 0 };
			info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
			info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
			SIZE_T cbInfo = sizeof(info);

			if (VMMDLL_ProcessGetInformation(detail::hVMM, pid, &info, &cbInfo)) {
				std::string p_name = info.szName;
				if (p_name.find(process_name) != std::string::npos) {
					matching_pids.push_back(pid);
				}
			}
		}

		for (const auto& pid : matching_pids) {
			for (const auto& child_pid : matching_pids) {
				if (pid == child_pid) {
					continue;
				}

				VMMDLL_PROCESS_INFORMATION child_info = { 0 };
				child_info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
				child_info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
				SIZE_T cbChildInfo = sizeof(child_info);

				if (VMMDLL_ProcessGetInformation(detail::hVMM, child_pid, &child_info, &cbChildInfo)) {
					if (child_info.dwPPID == pid) {
						return child_pid;
					}
				}
			}
		}

		return 0;
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