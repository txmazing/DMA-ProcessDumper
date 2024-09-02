#include <iostream>
#include <string>
#include "memory.hpp"
#include "dump.hpp"

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <PID>" << std::endl;
        return 1;
    }

    DWORD pid = static_cast<DWORD>(std::stoul(argv[1]));

    if (!memory::init(pid)) {
        std::cout << "Failed to initialize memory for process with PID: " << pid << std::endl;
        return 1;
    }

    if (!dumper::dump(pid)) {
        std::cout << "Failed to dump process with PID: " << pid << std::endl;
        return 1;
    }

    std::cout << "Process dump completed successfully." << std::endl;
    return 0;
}