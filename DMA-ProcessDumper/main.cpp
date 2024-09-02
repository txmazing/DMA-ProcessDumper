#include <Windows.h>
#include <iostream>

#include "memory.hpp"
#include "dump.hpp"

int main(int argc, char** argv)
{
    if (!memory::init("TslGame.exe"))
    {
        printf("[!] Failed to initialize memory\n");
        return -1;
    }

    if (!dumper::dump())
    {
        printf("[!] Failed to dump process\n");
        return -1;
    }

    return 0;
}