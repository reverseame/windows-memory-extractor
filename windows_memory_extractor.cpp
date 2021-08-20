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
#include <psapi.h>
#pragma comment( lib, "Version.lib" )


struct ArgumentManager {

	void validateArguments(int argc, char* argv[]) {

		namespace po = boost::program_options;
		std::string version = "v1.0.7";
		po::options_description description("Windows memory extractor " + version + "\nUsage");

		description.add_options()
			("help,h", "Display this help message")
			("file-version-info,i", "Retrieve version information about the file corresponding to a module")
			("join,j", "Generate an additional .dmp file with the contents of the other .dmp files joined")
			("module,m", po::value<std::string>(), "Module of the process")
			("output-directory,o", po::value<std::string>(), "Directory where the output will be stored")
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
			if (suppliedModule.length() > 255) {
				SetLastError(18);
				throw std::invalid_argument{ "The module name is too long" };
			}
			else {
				module = suppliedModule;
				isModuleOptionSupplied = true;
			}
		}

		if (vm.count("join")) {
			isJoinOptionSupplied = true;
			if (!isModuleOptionSupplied) {
				// The --join option was included to work alongside the --module option
				// If the --join option is supplied without the --module option, the tool interprets that the user is asking for the contents of the main module
				isModuleOptionSupplied = true;
			}
		}

		if (vm.count("file-version-info")) {
			isFileVersionInfoOptionSupplied = true;
			if (!isModuleOptionSupplied) {
				// As with the --join option, the --file-version-info option is implemented to work alongside the --module option
				// If the --file-version-info option is supplied without the --module option, the tool interprets that the user is asking for the version information of the file corresponding to the main module
				isModuleOptionSupplied = true;
			}
		}

		if (vm.count("pid")) {
			pid = vm["pid"].as<int>();
		}

		if (vm.count("protections")) {
			validateProtections(vm["protections"].as<std::string>());
		}

		if (vm.count("output-directory")) {
			if (directoryExists(vm["output-directory"].as<std::string>())) {
				outputDirectory = vm["output-directory"].as<std::string>();
				isOutputDirectoryOptionSupplied = true;
			}
			else {
				throw std::invalid_argument{ "The directory supplied does not exist" };
			}
		}

	}

	int getPid() {
		return pid;
	}

	void setModule(std::string newModule) {
		module = newModule;
	}

	std::string& getModule() {
		return module;
	}

	std::vector<std::string>& getProtections() {
		return protections;
	}

	std::string& getOutputDirectory() {
		return outputDirectory;
	}

	bool getIsModuleOptionSupplied() {
		return isModuleOptionSupplied;
	}

	bool getIsProtectionsOptionSupplied() {
		return isProtectionsOptionSupplied;
	}

	bool getIsJoinOptionSupplied() {
		return isJoinOptionSupplied;
	}

	bool getIsOutputDirectoryOptionSupplied() {
		return isOutputDirectoryOptionSupplied;
	}

	bool getIsFileVersionInfoOptionSupplied() {
		return isFileVersionInfoOptionSupplied;
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
				SetLastError(160);
				throw std::invalid_argument{ "The same memory protection cannot be supplied more than once" };
			}

			bool isProtectionSupported = std::find(supportedProtections.begin(), supportedProtections.end(), protection) != supportedProtections.end();
			if (isProtectionSupported) {
				protections.push_back(protection);
			}
			else {
				SetLastError(160);
				throw std::invalid_argument{ "The memory protections supplied are invalid. "
					"Supply only supported ones, separate each one with a space, and enclose all of them in quotes" };
			}
		}
		isProtectionsOptionSupplied = true;
	}

	bool directoryExists(const std::string& suppliedDirectoryAsString)
	{
		DWORD fileAttributes = GetFileAttributesA(suppliedDirectoryAsString.c_str());

		if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
			return false; // Something is wrong with the path
		}

		if (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			return true; // The path corresponds with a directory
		}

		return false; // The path does not correspond with a directory
	}

	// Arguments
	int pid;
	std::string module;
	std::vector<std::string> protections;
	std::string outputDirectory;

	// Options
	bool isModuleOptionSupplied;
	bool isProtectionsOptionSupplied;
	bool isJoinOptionSupplied;
	bool isOutputDirectoryOptionSupplied;
	bool isFileVersionInfoOptionSupplied;

};


struct MemoryExtractionManager {

	MemoryExtractionManager(ArgumentManager& argumentManagerReceived) : argumentManager{ argumentManagerReceived } {}

	void extractMemoryContents() {

		HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, argumentManager.getPid());
		if (processHandle == NULL) {

			// Try to enable SeDebugPrivilege and call OpenProcess again
			HANDLE accessToken;

			if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &accessToken) == FALSE) {
				throw std::exception{ "An error has occurred trying to enable SeDebugPrivlege at function OpenProcessToken" };
			}

			if (!SetPrivilege(accessToken, SE_DEBUG_NAME, true)) {
				CloseHandle(accessToken);
				throw std::exception{ "An error has occurred trying to enable SeDebugPrivlege at function SetPrivilege" };
			}

			processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, argumentManager.getPid());

			CloseHandle(accessToken);

			if (processHandle == NULL) {
				throw std::exception{ "A handle to the specified process could not be obtained" };
			}

		}

		if (argumentManager.getIsModuleOptionSupplied() && argumentManager.getModule().length() == 0) {
			// The user is asking for data about the main module
			char mainModulePathAsCharArray[MAX_PATH];
			if (GetProcessImageFileNameA(processHandle, mainModulePathAsCharArray, MAX_PATH) != 0) {
				std::string mainModulePath(mainModulePathAsCharArray);
				std::string mainModuleName(mainModulePath.substr(mainModulePath.rfind("\\") + 1));
				argumentManager.setModule(mainModuleName);
			}
			else {
				CloseHandle(processHandle);
				throw std::exception{ "The name of the main module could not be obtained" };
			}
		}

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

			if (argumentManager.getIsFileVersionInfoOptionSupplied()) {
				std::wstring modulePathW{ moduleInformation.szExePath };
				std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
				std::string modulePath = converter.to_bytes(modulePathW);
				DWORD dwHandle;
				DWORD fileVersionInfoSize = GetFileVersionInfoSizeA(modulePath.c_str(), &dwHandle);
				if (fileVersionInfoSize == 0) {
					throw std::exception{ "An error has occurred trying to get the version information at function GetFileVersionInfoSizeA" };
				}
				std::vector<unsigned char> fileVersionInfoBuffer(fileVersionInfoSize);
				if (!GetFileVersionInfoA(modulePath.c_str(), dwHandle, fileVersionInfoSize, &fileVersionInfoBuffer[0])) {
					throw std::exception{ "An error has occurred trying to get the version information at function GetFileVersionInfoA" };
				}
				directoryName = createDirectory();
				retrieveFileVersionInformation(&fileVersionInfoBuffer[0]);
			}
		}

		if (!isDirectoryCreated) {
			directoryName = createDirectory();
		}

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
		if (argumentManager.getIsJoinOptionSupplied()) {
			using namespace CryptoPP;
			dmpFilesGeneratedCount++;

			// Calculate the SHA-256 of the file joinedModuleContents.dmp
			std::ifstream joinedModuleContentsStream(directoryName + "/joinedModuleContents.dmp", std::ios::in | std::ios::binary);
			std::string contents((std::istreambuf_iterator<char>(joinedModuleContentsStream)),
				(std::istreambuf_iterator<char>()));
			HexEncoder hexEncoder(new FileSink(resultsFile), false);
			std::string sha256Digest;
			SHA256 hash;
			hash.Update((const byte*)contents.c_str(), contents.length());
			sha256Digest.resize(hash.DigestSize());
			hash.Final((byte*)&sha256Digest[0]);

			// Create an entry in the results file for the joinedModuleContents.dmp file
			resultsFile << "Filename: " << "joinedModuleContents.dmp" << ", SHA-256: ";
			StringSource(sha256Digest, true, new Redirector(hexEncoder));
			resultsFile << "\n";

			joinedModuleContentsStream.close();
		}

		resultsFile << "Number of .dmp files generated: " << dmpFilesGeneratedCount << "\n";

		if (argumentManager.getIsFileVersionInfoOptionSupplied()) {
			resultsFile << "\nAdditional files generated:\n";

			using namespace CryptoPP;
			dmpFilesGeneratedCount++;

			// Calculate the SHA-256 of the file moduleFileVersionInfo.fileinfo
			std::ifstream moduleFileVersionInfoStream(directoryName + "/moduleFileVersionInfo.fileinfo", std::ios::in | std::ios::binary);
			std::string contents((std::istreambuf_iterator<char>(moduleFileVersionInfoStream)),
				(std::istreambuf_iterator<char>()));
			HexEncoder hexEncoder(new FileSink(resultsFile), false);
			std::string sha256Digest;
			SHA256 hash;
			hash.Update((const byte*)contents.c_str(), contents.length());
			sha256Digest.resize(hash.DigestSize());
			hash.Final((byte*)&sha256Digest[0]);

			// Create an entry in the results file for the moduleFileVersionInfo.fileinfo file
			resultsFile << "Filename: " << "moduleFileVersionInfo.fileinfo" << ", SHA-256: ";
			StringSource(sha256Digest, true, new Redirector(hexEncoder));
			resultsFile << "\n";

			moduleFileVersionInfoStream.close();
		}

		resultsFile << std::endl;
		resultsFile.close();
		CloseHandle(processHandle);
	}

private:

	MODULEENTRY32 getModuleInformation(std::string& suppliedModuleName) {
		HANDLE snapshotHandle = INVALID_HANDLE_VALUE;
		MODULEENTRY32 moduleEntry;

		// Get a snapshot of all the modules
		snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, argumentManager.getPid());
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
		if (argumentManager.getIsOutputDirectoryOptionSupplied()) {
			directoryNameStream << argumentManager.getOutputDirectory() << "/";
		}
		directoryNameStream << std::dec << argumentManager.getPid() << "_" << std::put_time(&buf, "%d-%m-%Y_%H-%M-%S_UTC");
		CreateDirectoryA(directoryNameStream.str().c_str(), NULL);
		isDirectoryCreated = true;
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

			// Each .dmp file that corresponds to one memory region has a representative name
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

			if (argumentManager.getIsJoinOptionSupplied()) {
				std::string fullModuleFilePath = directoryName + "/" + "joinedModuleContents.dmp";
				std::ofstream fullModuleDataFile(fullModuleFilePath, std::ofstream::app | std::ofstream::binary);
				fullModuleDataFile.write(memoryContents.get(), memInfo.RegionSize);
				fullModuleDataFile.close();
			}
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

	// Function found here: https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
	BOOL SetPrivilege(
		HANDLE hToken,          // access token handle
		LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
		BOOL bEnablePrivilege   // to enable or disable privilege
	)
	{
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!LookupPrivilegeValue(
			NULL,            // lookup privilege on local system
			lpszPrivilege,   // privilege to lookup 
			&luid))        // receives LUID of privilege
		{
			printf("LookupPrivilegeValue error: %u\n", GetLastError());
			return FALSE;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (bEnablePrivilege)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		// Enable the privilege or disable all privileges.

		if (!AdjustTokenPrivileges(
			hToken,
			FALSE,
			&tp,
			sizeof(TOKEN_PRIVILEGES),
			(PTOKEN_PRIVILEGES)NULL,
			(PDWORD)NULL))
		{
			printf("AdjustTokenPrivileges error: %u\n", GetLastError());
			return FALSE;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

		{
			printf("The token does not have the specified privilege. \n");
			return FALSE;
		}

		return TRUE;
	}

	void retrieveFileVersionInformation(LPCVOID fileVersionInfoBufferPointer) {
		std::vector<std::string> versionInfoKeys{
			"Comments",
			"CompanyName",
			"FileDescription",
			"FileVersion",
			"InternalName",
			"LegalCopyright",
			"LegalTrademarks",
			"OriginalFilename",
			"ProductName",
			"ProductVersion",
			"PrivateBuild",
			"SpecialBuild"
		};

		struct LANGANDCODEPAGE {
			WORD wLanguage;
			WORD wCodePage;
		} *lpTranslate;

		UINT cbTranslate = 0;
		if (!VerQueryValueA(fileVersionInfoBufferPointer, "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
			throw std::exception{ "An error has occurred trying to get the version information at function VerQueryValueA" };
		}

		std::ofstream moduleVersionInfoFile(directoryName + "/moduleFileVersionInfo.fileinfo", std::ofstream::out);

		for (unsigned int i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++) {
			BOOST_FOREACH(const std::string & versionInfoKey, versionInfoKeys) {
				std::string versionInfoKeyFormat = "\\StringFileInfo\\%04x%04x\\" + versionInfoKey;
				char versionInfoKeyWithLanguage[256];
				sprintf_s(versionInfoKeyWithLanguage, versionInfoKeyFormat.c_str(), lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
				LPSTR versionInfoValuePointer = NULL;
				UINT  versionInfoValueSize = 0;
				if (VerQueryValueA(fileVersionInfoBufferPointer, versionInfoKeyWithLanguage, (LPVOID*)&versionInfoValuePointer, &versionInfoValueSize)) {
					moduleVersionInfoFile << versionInfoKey << "," << std::string(versionInfoValuePointer) << "\n";
				}
				else {
					// The value for the key is empty
					moduleVersionInfoFile << versionInfoKey << ",\n";
				}
			}
		}
		moduleVersionInfoFile.close();
	}

	ArgumentManager& argumentManager;
	std::string directoryName; // The directory where the memory data files will be placed
	bool isDirectoryCreated;
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
			exit(GetLastError());
		}
		catch (...) {
			std::cerr << "Error: An unexpected error has occurred." << std::endl;
			exit(GetLastError());
		}
	}

};


int main(int argc, char* argv[]) {

	ExecutionManager executionManager{};
	executionManager.execute(argc, argv);

}