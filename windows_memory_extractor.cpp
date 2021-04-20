#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <ctime>
#include <algorithm>
#include <iomanip>


void dumpMemory(HANDLE processHandle, char* pid) {

	// Create a directory with a representative name
	// Nomenclature: PID_Day-Month-Year_Hour-Minute-Second_UTC

	std::string pidAsString{ pid };

	std::time_t timestamp = std::time(nullptr);
	std::stringstream timestampStream;
	timestampStream << std::put_time(std::gmtime(&timestamp), "%d-%m-%Y_%H-%M-%S_UTC");
	std::string timestampAsString{ timestampStream.str() };

	std::string directoryName = pidAsString + "_" + timestampAsString;

	CreateDirectory(directoryName.c_str(), NULL);

	unsigned char* p = NULL;
	MEMORY_BASIC_INFORMATION memInfo;

	// Create files that contain raw memory data inside the directory prevously created
	while (VirtualQueryEx(processHandle, p, &memInfo, sizeof(memInfo)) != 0) {

		if (memInfo.State == MEM_COMMIT && (memInfo.AllocationProtect == PAGE_READONLY || memInfo.AllocationProtect == PAGE_READWRITE)) {
			auto memoryContents = std::make_unique<char[]>(memInfo.RegionSize);
			SIZE_T numberOfBytesRead = 0;

			if (ReadProcessMemory(processHandle, p, memoryContents.get(), memInfo.RegionSize, &numberOfBytesRead) != 0) {

				// Each file has a representative name
				// Nomenclature: virtualAddress_sizeOfMemoryRegion

				char virtualAddressAsCharArray[17];
				snprintf(virtualAddressAsCharArray, 17, "%p", memInfo.BaseAddress);

				std::string virtualAddressAsString{ virtualAddressAsCharArray };
				std::transform(virtualAddressAsString.begin(), virtualAddressAsString.end(), virtualAddressAsString.begin(), ::tolower);

				std::stringstream hexadecimalStream;
				hexadecimalStream << std::hex << memInfo.RegionSize;
				std::string regionSizeAsString{ hexadecimalStream.str() };

				std::string fileName = directoryName + "/0x" + virtualAddressAsString + "_0x" + regionSizeAsString;

				std::ofstream outfile(fileName, std::ofstream::binary);
				outfile.write(memoryContents.get(), memInfo.RegionSize);
				outfile.close();
			}
		}

		p += memInfo.RegionSize;
	}
}


int main(int argc, char* argv[]) {

	if (argc != 2) {
		printf("Usage: %s pid [-m module]", argv[0]);
		exit(1);
	}

	int pid;

	// Validate the PID supplied by the user
	try {
		pid = std::stoi(std::string{ argv[1] });
	}
	catch (const std::invalid_argument&) {
		fprintf(stderr, "Error: The PID is not a valid number\n");
		exit(1);
	}
	catch (const std::out_of_range&) {
		fprintf(stderr, "Error: The PID supplied is too big\n");
		exit(1);
	}
	catch (...) {
		fprintf(stderr, "Error: An unexpected error has occurred\n");
		exit(1);
	}

	try {
		HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (processHandle == NULL) {
			fprintf(stderr, "Error: A handle to the process specified could not be obtained\n");
			exit(1);
		}
		dumpMemory(processHandle, argv[1]);
		CloseHandle(processHandle);
	}
	catch (const std::exception& ex) {
		fprintf(stderr, "Error: %s\n", ex.what());
		exit(1);
	}
	catch (...) {
		fprintf(stderr, "Error: An unexpected error has occurred\n");
		exit(1);
	}

}