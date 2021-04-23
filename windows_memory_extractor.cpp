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
#include <getopt.h>


struct ArgumentManager {

	void validateArguments(int argc, char* argv[]) {
		char* suppliedPid, * suppliedModule, * suppliedProtections;

		int option;
		int option_index = 0;

		static struct option availableOptions[] =
		{
			{"help",        no_argument,       0, 'h'},
			{"module",      required_argument, 0, 'm'},
			{"protections", required_argument, 0, 'p'},
			{0, 0, 0, 0}
		};

		// Check if optional arguments were supplied correctly
		while ((option = getopt_long(argc, argv, "hp:m:", availableOptions, &option_index)) != -1) {

			switch (option) {
			case 'h':
				displayHelp();
				exit(0);

			case 'm':
				printf("option -m has the value `%s'\n", optarg);
				suppliedModule = optarg;
				isModuleOptionSupplied = true;
				break;

			case 'p':
				printf("option -p has the value `%s'\n", optarg);
				suppliedProtections = optarg;
				isProtectionsOptionSupplied = true;
				break;

			default:
				exit(1);
			}
		}

		// Check if only one mandatory argument was supplied
		if (optind == argc - 1) {
			printf("PID supplied: %s\n", argv[optind]);
			suppliedPid = argv[optind];
		}
		else {
			fprintf(stderr, "One, and only one, mandatory argument has to be supplied\n");
			exit(1);
		}

		// Validate the contents of the arguments
		pid = validatePid(suppliedPid);
	}

	int getPid() {
		return pid;
	}

	std::string getModule() {
		return module;
	}

	std::string getProtections() {
		return protections;
	}

	bool getIsModuleOptionSupplied() {
		return isModuleOptionSupplied;
	}

	bool getIsProtectionsOptionSupplied() {
		return isProtectionsOptionSupplied;
	}

private:

	void displayHelp() {
		printf("This is the help text the user would see.\n");
	}

	int validatePid(char* suppliedPid) {
		try {
			return std::stoi(std::string{ suppliedPid });
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
	}

	// Arguments
	int pid;
	std::string module;
	std::string protections;

	// Options
	bool isModuleOptionSupplied;
	bool isProtectionsOptionSupplied;

};

struct MemoryExtractionManager {

	MemoryExtractionManager(ArgumentManager& argumentManagerReceived) : argumentManager{ argumentManagerReceived } {}

	void extractMemoryContents() {

		HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, argumentManager.getPid());

		if (processHandle == NULL) {
			fprintf(stderr, "Error: A handle to the process specified could not be obtained\n");
			exit(1);
		}

		// Create a directory with a representative name
		// Nomenclature: PID_Day-Month-Year_Hour-Minute-Second_UTC

		std::time_t timestamp = std::time(nullptr);
		std::stringstream directoryName;
		directoryName << std::dec << argumentManager.getPid() << "_" << std::put_time(std::gmtime(&timestamp), "%d-%m-%Y_%H-%M-%S_UTC");
		CreateDirectory(directoryName.str().c_str(), NULL);

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

					std::stringstream fileName;
					fileName << memInfo.BaseAddress << "_" << std::hex << memInfo.RegionSize << ".dmp";

					std::string filePath = directoryName.str() + "/" + fileName.str().erase(0, 2);

					std::ofstream outfile(filePath, std::ofstream::binary);
					outfile.write(memoryContents.get(), memInfo.RegionSize);
					outfile.close();
				}
			}

			p += memInfo.RegionSize;
		}

		CloseHandle(processHandle);
	}

private:

	ArgumentManager& argumentManager;

};


struct ExecutionManager {

	void execute(int argc, char* argv[]) {
		try {
			ArgumentManager argumentManager{};
			argumentManager.validateArguments(argc, argv);
			MemoryExtractionManager memoryExtractionManager{ argumentManager };
			memoryExtractionManager.extractMemoryContents();
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

};


int main(int argc, char* argv[]) {

	ExecutionManager executionManager{};
	executionManager.execute(argc, argv);

}