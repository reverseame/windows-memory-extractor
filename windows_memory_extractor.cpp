#define WIN32_LEAN_AND_MEAN
#define __STDC_WANT_LIB_EXT1__ 1
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <ctime>
#include <time.h>
#include <algorithm>
#include <iomanip>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>


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
		struct tm buf;
		gmtime_s(&buf, &timestamp);
		std::stringstream directoryNameStream;
		directoryNameStream << std::dec << argumentManager.getPid() << "_" << std::put_time(&buf, "%d-%m-%Y_%H-%M-%S_UTC");
		CreateDirectoryA(directoryNameStream.str().c_str(), NULL);

		std::ofstream resultsFile( directoryNameStream.str() + "/results.txt", std::ofstream::out);
		resultsFile << "List of .dmp files generated:\n";
		int dmpFilesGeneratedCount = 0;

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

					std::stringstream fileNameStream;
					fileNameStream << memInfo.BaseAddress << "_" << std::hex << memInfo.RegionSize << ".dmp";
					std::string fileName = fileNameStream.str();
					boost::algorithm::to_lower(fileName);

					std::string filePath = directoryNameStream.str() + "/" + fileName;

					std::ofstream memoryDataFile(filePath, std::ofstream::binary);
					memoryDataFile.write(memoryContents.get(), memInfo.RegionSize);
					memoryDataFile.close();

					dmpFilesGeneratedCount++;
					registerDmpFileCreation(fileName, memoryContents.get(), memInfo.RegionSize, resultsFile);
				}
			}

			p += memInfo.RegionSize;
		}

		resultsFile << "Number of .dmp files generated: " << dmpFilesGeneratedCount << std::endl;
		resultsFile.close();
		CloseHandle(processHandle);
	}

private:

	void registerDmpFileCreation(std::string& fileName, char* fileContents, size_t fileSize, std::ofstream& resultsFile) {
		using namespace CryptoPP;

		// Calculate the SHA-256 hash of the .dmp file contents
		HexEncoder hexEncoder(new FileSink(resultsFile), false);
		std::string sha256Digest;
		SHA256 hash;
		hash.Update((const byte*)fileContents, fileSize);
		sha256Digest.resize(hash.DigestSize());
		hash.Final((byte*)&sha256Digest[0]);

		// Create an entry in the results file for the new .dmp file
		resultsFile << fileName << ", SHA-256: ";
		StringSource(sha256Digest, true, new Redirector(hexEncoder));
		resultsFile << "\n";
	}

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