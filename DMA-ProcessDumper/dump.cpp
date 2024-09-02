#include "dump.hpp"

bool dumper::dump(DWORD pid)
{
    printf("[>] Dumping process with PID %d...\n", pid);
    if (!memory::detail::process_id ||
        !memory::detail::process_base_address ||
        !memory::detail::process_size
        )
    {
        printf("[!] Memory is not initialized.\n");
        return false;
    }
    auto buffer = (BYTE*)malloc(memory::detail::process_size);
    if (!buffer)
    {
        printf("[!] Failed to allocate buffer (Error: %d)\n", GetLastError());
        return false;
    }
    printf("[+] Buffer allocated at 0x%p\n", buffer);
    for (ULONG iterator = 0x0; iterator < memory::detail::process_size; iterator += 0x1000)
    {
        if (!memory::read_buffer(memory::detail::process_base_address + iterator, buffer + iterator, 0x1000))
        {
            printf("[!] Failed to read buffer at 0x%lX (Error: %d)\n",
                memory::detail::process_base_address + iterator, GetLastError());
            free(buffer);
            return false;
        }
    }
    auto pdos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
    if (!pdos_header->e_lfanew)
    {
        printf("[!] Failed to get DOS header from buffer\n");
        free(buffer);
        return false;
    }
    printf("[+] DOS header read: %p\n", pdos_header);
    if (pdos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[!] Invalid DOS header signature\n");
        free(buffer);
        return false;
    }
    auto pnt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer + pdos_header->e_lfanew);
    if (!pnt_header)
    {
        printf("[!] Failed to read NT header from buffer\n");
        free(buffer);
        return false;
    }
    printf("[+] NT header read: 0x%p\n", pnt_header);
    if (pnt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[!] Invalid NT header signature from read NT header\n");
        free(buffer);
        return false;
    }
    auto poptional_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&pnt_header->OptionalHeader);
    if (!poptional_header)
    {
        printf("[!] Failed to read optional header from buffer\n");
        free(buffer);
        return false;
    }
    printf("[+] Optional header read: 0x%p\n", poptional_header);
    int i = 0;
    unsigned int section_offset = poptional_header->SizeOfHeaders;
    for (
        PIMAGE_SECTION_HEADER psection_header = IMAGE_FIRST_SECTION(pnt_header);
        i < pnt_header->FileHeader.NumberOfSections;
        i++, psection_header++
        )
    {
        psection_header->Misc.VirtualSize = psection_header->SizeOfRawData;
        memcpy(buffer + section_offset, psection_header, sizeof(IMAGE_SECTION_HEADER));
        section_offset += sizeof(IMAGE_SECTION_HEADER);
        if (!memory::read_buffer(
            poptional_header->ImageBase + psection_header->VirtualAddress,
            buffer + psection_header->PointerToRawData,
            psection_header->SizeOfRawData
        ))
        {
            printf("[!] Failed to read buffer from headers\n");
            free(buffer);
            return false;
        }
    }
    char FileName[MAX_PATH];
    sprintf_s(FileName, "%s%d_dump.exe", util::get_path().c_str(), pid);

    std::ofstream Dump(FileName, std::ios::binary);
    Dump.write((char*)buffer, memory::detail::process_size);
    Dump.close();
    printf("[>] Dumped successfully to %s\n", FileName);
    free(buffer);
    return true;
}