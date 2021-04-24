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
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>


struct ArgumentManager {

	void validateArguments(int argc, char* argv[]) {

		namespace po = boost::program_options;
		po::options_description description("Usage");

		description.add_options()
			("help,h", "Display the help message")
			("module,m", po::value<std::string>(), "Module")
			("pid,p", po::value<int>()->required(), "Process ID")
			("protections,s", po::value<std::string>(), "Memory protections")
			;

		po::variables_map vm;
		po::store(po::command_line_parser(argc, argv).options(description).run(), vm);

		if (vm.count("help")) {
			std::cout << description << std::endl;
			exit(0);
		}

		po::notify(vm);

		if (vm.count("module")) {
			std::cout << "Module: " << vm["module"].as<std::string>() << std::endl;
		}

		if (vm.count("pid")) {
			std::cout << "Pid: " << vm["pid"].as<int>() << std::endl;
			pid = vm["pid"].as<int>();
		}

		if (vm.count("protections")) {
			std::cout << "Protections: " << vm["protections"].as<std::string>() << std::endl;
		}

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
			std::cerr << "Error: A handle to the process specified could not be obtained." << std::endl;
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

					std::string filePath = directoryName.str() + "/" + boost::algorithm::to_lower_copy(fileName.str().erase(0, 2));

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
			std::cerr << "Error: " << ex.what() << "." << std::endl;
			exit(1);
		}
		catch (...) {
			std::cerr << "Error: An unexpected error has occurred." << std::endl;
			exit(1);
		}
	}

};


int main(int argc, char* argv[]) {

	ExecutionManager executionManager{};
	executionManager.execute(argc, argv);

}