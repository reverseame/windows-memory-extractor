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
#include <tlhelp32.h> 
#include <tchar.h> 
#include <locale>
#include <codecvt>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>


struct ArgumentManager {

	void validateArguments(int argc, char* argv[]) {

		namespace po = boost::program_options;
		std::string version = "1.0";
		po::options_description description("Windows memory extractor " + version + "\nUsage");

		description.add_options()
			("help,h", "Display this help message")
			("module,m", po::value<std::string>(), "Module of the process")
			("pid,p", po::value<int>()->required(), "Process ID")
			("protections,s", po::value<std::string>(), "Memory protections")
			("version,v", "Version")
			;

		po::variables_map vm;
		po::store(po::command_line_parser(argc, argv).options(description).run(), vm);

		if (vm.count("help")) {
			std::cout << description << std::endl;
			exit(0);
		}

		if (vm.count("version")) {
			std::cout << "Windows memory extractor " << version << std::endl;
			exit(0);
		}

		po::notify(vm);

		if (vm.count("module")) {
			std::string suppliedModule = vm["module"].as<std::string>();
			if (suppliedModule.length() > 37) {
				throw std::invalid_argument{ "The module name is too long" };
			}
			else {
				module = suppliedModule;
				isModuleOptionSupplied = true;
			}
		}

		if (vm.count("pid")) {
			pid = vm["pid"].as<int>();
		}

		if (vm.count("protections")) {
			validateProtections(vm["protections"].as<std::string>());
		}

	}

	int getPid() {
		return pid;
	}

	std::string& getModule() {
		return module;
	}

	std::vector<std::string>& getProtections() {
		return protections;
	}

	bool getIsModuleOptionSupplied() {
		return isModuleOptionSupplied;
	}

	bool getIsProtectionsOptionSupplied() {
		return isProtectionsOptionSupplied;
	}

private:

	void validateProtections(std::string suppliedProtectionsAsString) {
		std::vector<std::string> supportedProtections{
			"PAGE_EXECUTE",
			"PAGE_EXECUTE_READ",
			"PAGE_EXECUTE_READWRITE",
			"PAGE_EXECUTE_WRITECOPY",
			"PAGE_READONLY",
			"PAGE_READWRITE",
			"PAGE_WRITECOPY"
		};
		std::vector<std::string> suppliedProtections;
		boost::split(suppliedProtections, suppliedProtectionsAsString, boost::is_any_of(" "));
		BOOST_FOREACH(const std::string & protection, suppliedProtections) {
			bool isProtectionRepeated = std::find(protections.begin(), protections.end(), protection) != protections.end();
			if (isProtectionRepeated) {
				throw std::invalid_argument{ "The same memory protection cannot be supplied more than once" };
			}

			bool isProtectionSupported = std::find(supportedProtections.begin(), supportedProtections.end(), protection) != supportedProtections.end();
			if (isProtectionSupported) {
				protections.push_back(protection);
			}
			else {
				throw std::invalid_argument{ "The memory protections supplied are invalid. "
					"Supply only supported ones, separate each one with a space, and enclose all of them in quotes" };
			}
		}
		isProtectionsOptionSupplied = true;
	}

	// Arguments
	int pid;
	std::string module;
	std::vector<std::string> protections;

	// Options
	bool isModuleOptionSupplied;
	bool isProtectionsOptionSupplied;

};


struct MemoryExtractionManager {

	MemoryExtractionManager(ArgumentManager& argumentManagerReceived) : argumentManager{ argumentManagerReceived } {}

	void extractMemoryContents() {

		BYTE* memoryPointer = NULL; // Virtual address 0x0000000000000000

		// Module option related variables
		BYTE* moduleBaseAddress;
		DWORD moduleSize;
		size_t moduleBaseAddressAsNumber;

		// If the --module option is supplied, I only extract the memory corresponding to the requiered module
		// In order to do that, I start at the module's base address, instead of at virtual address 0x0000000000000000
		if (argumentManager.getIsModuleOptionSupplied()) {
			MODULEENTRY32 moduleInformation = getModuleInformation(argumentManager.getModule());
			memoryPointer = moduleInformation.modBaseAddr;
			moduleBaseAddress = moduleInformation.modBaseAddr;
			moduleSize = moduleInformation.modBaseSize;
			moduleBaseAddressAsNumber = reinterpret_cast<size_t>(moduleInformation.modBaseAddr);
		}

		HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, argumentManager.getPid());
		if (processHandle == NULL) {
			throw std::exception{ "A handle to the specified process could not be obtained" };
		}

		directoryName = createDirectory();

		std::ofstream resultsFile(directoryName + "/results.txt", std::ofstream::out);
		resultsFile << "List of .dmp files generated:\n";

		MEMORY_BASIC_INFORMATION memInfo;
		bool isMemoryExtractionFinished = false;
		bool isModuleOptionSupplied = argumentManager.getIsModuleOptionSupplied();

		// Create files that contain raw memory data inside the directory prevously created
		while (VirtualQueryEx(processHandle, memoryPointer, &memInfo, sizeof(memInfo)) != 0 && !isMemoryExtractionFinished) {

			if (makeExtractionDecision(memInfo)) {
				extractMemoryRegion(processHandle, memInfo, resultsFile);
			}

			memoryPointer += memInfo.RegionSize;

			if (isModuleOptionSupplied && (reinterpret_cast<size_t>(memoryPointer) >= moduleBaseAddressAsNumber + moduleSize)) {
				isMemoryExtractionFinished = true;
			}

		}

		resultsFile << "Number of .dmp files generated: " << dmpFilesGeneratedCount << std::endl;
		resultsFile.close();
		CloseHandle(processHandle);
	}

private:

	MODULEENTRY32 getModuleInformation(std::string& suppliedModuleName) {
		HANDLE snapshotHandle = INVALID_HANDLE_VALUE;
		MODULEENTRY32 moduleEntry;

		// Get a snapshot of all the modules
		snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, argumentManager.getPid());
		if (snapshotHandle == INVALID_HANDLE_VALUE) {
			throw std::exception{ "The modules of the specified process could not be retrieved" };
		}

		moduleEntry.dwSize = sizeof(MODULEENTRY32);

		// Get the information about the first module 
		if (!Module32First(snapshotHandle, &moduleEntry)) {
			CloseHandle(snapshotHandle);
			throw std::exception{ "The information of the first module could not be retrieved" };
		}

		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> stringConverter;
		std::string moduleName;

		// Get the information about the rest of the modules 
		do {
			moduleName = stringConverter.to_bytes(moduleEntry.szModule);
			boost::algorithm::to_lower(moduleName);
			if (boost::iequals(suppliedModuleName, moduleName)) {
				CloseHandle(snapshotHandle);
				return moduleEntry;
			}

		} while (Module32Next(snapshotHandle, &moduleEntry));

		CloseHandle(snapshotHandle);
		throw std::invalid_argument{ "The module was not found in the specified process" };
	}

	std::string createDirectory() {

		// The directory created has a representative name
		// Nomenclature: PID_Day-Month-Year_Hour-Minute-Second_UTC

		std::time_t timestamp = std::time(nullptr);
		struct tm buf;
		gmtime_s(&buf, &timestamp);
		std::stringstream directoryNameStream;
		directoryNameStream << std::dec << argumentManager.getPid() << "_" << std::put_time(&buf, "%d-%m-%Y_%H-%M-%S_UTC");
		CreateDirectoryA(directoryNameStream.str().c_str(), NULL);
		return directoryNameStream.str();
	}

	bool makeExtractionDecision(MEMORY_BASIC_INFORMATION& memInfo) {
		DWORD state = memInfo.State;
		DWORD protection = memInfo.Protect;
		if (argumentManager.getIsProtectionsOptionSupplied()) {
			std::vector<std::string>& protections = argumentManager.getProtections();
			bool isPageExecuteSupplied = std::find(protections.begin(), protections.end(), "PAGE_EXECUTE") != protections.end();
			bool isPageExecuteReadSupplied = std::find(protections.begin(), protections.end(), "PAGE_EXECUTE_READ") != protections.end();
			bool isPageExecuteReadWriteSupplied = std::find(protections.begin(), protections.end(), "PAGE_EXECUTE_READWRITE") != protections.end();
			bool isPageExecuteWriteCopySupplied = std::find(protections.begin(), protections.end(), "PAGE_EXECUTE_WRITECOPY") != protections.end();
			bool isPageReadOnlySupplied = std::find(protections.begin(), protections.end(), "PAGE_READONLY") != protections.end();
			bool isPageReadWriteSupplied = std::find(protections.begin(), protections.end(), "PAGE_READWRITE") != protections.end();
			bool isPageWriteCopySupplied = std::find(protections.begin(), protections.end(), "PAGE_WRITECOPY") != protections.end();
			return state == MEM_COMMIT
				&& ((protection == PAGE_EXECUTE && isPageExecuteSupplied)
					|| (protection == PAGE_EXECUTE_READ && isPageExecuteReadSupplied)
					|| (protection == PAGE_EXECUTE_READWRITE && isPageExecuteReadWriteSupplied)
					|| (protection == PAGE_EXECUTE_WRITECOPY && isPageExecuteWriteCopySupplied)
					|| (protection == PAGE_READONLY && isPageReadOnlySupplied)
					|| (protection == PAGE_READWRITE && isPageReadWriteSupplied)
					|| (protection == PAGE_WRITECOPY && isPageWriteCopySupplied)
					);
		}
		else if (argumentManager.getIsModuleOptionSupplied()) {
			return state == MEM_COMMIT
				&& (protection == PAGE_EXECUTE
					|| protection == PAGE_EXECUTE_READ
					|| protection == PAGE_EXECUTE_READWRITE
					|| protection == PAGE_EXECUTE_WRITECOPY
					|| protection == PAGE_READONLY
					|| protection == PAGE_READWRITE
					|| protection == PAGE_WRITECOPY
					);
		}
		else {
			return state == MEM_COMMIT
				&& (protection == PAGE_READONLY
					|| protection == PAGE_READWRITE
					|| protection == PAGE_WRITECOPY
					);
		}
	}

	void extractMemoryRegion(HANDLE& processHandle, MEMORY_BASIC_INFORMATION& memInfo, std::ofstream& resultsFile) {
		auto memoryContents = std::make_unique<char[]>(memInfo.RegionSize);
		SIZE_T numberOfBytesRead = 0;

		if (ReadProcessMemory(processHandle, memInfo.BaseAddress, memoryContents.get(), memInfo.RegionSize, &numberOfBytesRead) != 0) {

			// Each .dmp file has a representative name
			// Nomenclature: virtualAddress_sizeOfMemoryRegion

			std::stringstream fileNameStream;
			fileNameStream << memInfo.BaseAddress << "_" << std::hex << memInfo.RegionSize << ".dmp";
			std::string fileName = fileNameStream.str();
			boost::algorithm::to_lower(fileName);

			std::string filePath = directoryName + "/" + fileName;

			std::ofstream memoryDataFile(filePath, std::ofstream::binary);
			memoryDataFile.write(memoryContents.get(), memInfo.RegionSize);
			memoryDataFile.close();

			dmpFilesGeneratedCount++;
			registerDmpFileCreation(fileName, memoryContents.get(), memInfo, resultsFile);
		}
	}

	void registerDmpFileCreation(std::string& fileName, char* fileContents, MEMORY_BASIC_INFORMATION& memInfo, std::ofstream& resultsFile) {
		using namespace CryptoPP;

		// Calculate the SHA-256 hash of the .dmp file contents
		HexEncoder hexEncoder(new FileSink(resultsFile), false);
		std::string sha256Digest;
		SHA256 hash;
		hash.Update((const byte*)fileContents, memInfo.RegionSize);
		sha256Digest.resize(hash.DigestSize());
		hash.Final((byte*)&sha256Digest[0]);

		// Create an entry in the results file for the new .dmp file
		resultsFile << "Filename: " << fileName << ", SHA-256: ";
		StringSource(sha256Digest, true, new Redirector(hexEncoder));
		std::string memoryProtection;
		switch (memInfo.Protect) {
		case PAGE_EXECUTE: {
			memoryProtection = "PAGE_EXECUTE";
			break;
		}
		case PAGE_EXECUTE_READ: {
			memoryProtection = "PAGE_EXECUTE_READ";
			break;
		}
		case PAGE_EXECUTE_READWRITE: {
			memoryProtection = "PAGE_EXECUTE_READWRITE";
			break;
		}
		case PAGE_EXECUTE_WRITECOPY: {
			memoryProtection = "PAGE_EXECUTE_WRITECOPY";
			break;
		}
		case PAGE_READONLY: {
			memoryProtection = "PAGE_READONLY";
			break;
		}
		case PAGE_READWRITE: {
			memoryProtection = "PAGE_READWRITE";
			break;
		}
		case PAGE_WRITECOPY: {
			memoryProtection = "PAGE_WRITECOPY";
			break;
		}
		default: {
			memoryProtection = "The memory protection is not supported by this tool yet";
		}
		}
		resultsFile << ", Memory protection: " << memoryProtection << "\n";
	}

	ArgumentManager& argumentManager;
	std::string directoryName; // The directory where the memory data files will be placed
	unsigned int dmpFilesGeneratedCount;

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