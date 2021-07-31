# Windows Memory Extractor
Tool to extract contents from the memory of Windows systems. 

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Installation
This tool is a portable application that does not need to be installed in order to be used. The steps to compile the application in a Windows system from the source code stored in this repository are listed below:

* Download the [Visual Studio IDE](https://visualstudio.microsoft.com/) and install, at least, the *Desktop development with C++* features.
* Install the [Boost C++ libraries](https://www.boost.org/), build the ones that need to be compiled, and configure the Visual Studio IDE to use them. The instructions to do this are described [here](https://www.boost.org/doc/libs/1_76_0/more/getting_started/windows.html).
* Install the [vcpkg dependency manager](https://github.com/Microsoft/vcpkg/) following [these](https://github.com/Microsoft/vcpkg/#quick-start-windows) steps.
* Install the [Crypto++ library](https://www.cryptopp.com/) using vcpkg, explained in the section *BUILDING WITH VCPKG* of the [Crypto++ installation documentation](https://github.com/weidai11/cryptopp/blob/master/Install.txt).

After following these steps, all the application dependencies will be installed and the tool can be compiled using the Visual Studio IDE.

## Usage
This tool is a command line application. In order to extract the non executable memory regions of a proccess whose PID is, for instance, 1234, the following command can be executed:

```bash
.\WindowsMemoryExtractor_x64.exe --pid 1234 
```

Instead of extracting only the non executable memory regions, you can indicate that you want to extract only memory regions whose protections match the ones you provide as a command line argument. To extract, for example, the memory regions whose protections are either PAGE_READONLY or PAGE_EXECUTE_READ from the process whose PID is 1234, execute the command below:

```bash
.\WindowsMemoryExtractor_x64.exe --pid 1234 --protections "PAGE_READONLY PAGE_EXECUTE_READ"
```

The memory protections supported are PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE and PAGE_WRITECOPY. Their respective meanings can be checked [here](https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants).

In addition, the tool allows you to specify a module of the process in order to extract only the memory regions of that module. The following command will extract the memory regions whose protections are either PAGE_READONLY or PAGE_EXECUTE_READ from the module *user32.dll* of the process whose PID is 1234:

```bash
.\WindowsMemoryExtractor_x64.exe --pid 1234 --protections "PAGE_READONLY PAGE_EXECUTE_READ" --module user32.dll
```

By default, if a module is provided but no memory protections are indicated, all the memory regions of that module whose protections match the supported ones will be extracted. The tool also has the --join option, in order to obtain the solicited memory regions of a module in one file. Additionally, if the user wants to get the version information about the file corresponding to a module, there is the --file-version-info option. Finally, for additional help, execute the command below:

```bash
.\WindowsMemoryExtractor_x64.exe --help
```

## License
GNU General Public License v3.0
