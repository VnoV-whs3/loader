#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <io.h>
#include <fcntl.h>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")

class SimpleCrypto {
private:
    std::vector<BYTE> key = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    std::vector<BYTE> iv = { 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89 };

public:
    std::vector<BYTE> Decrypt(const std::vector<BYTE>& encryptedData) {
        std::vector<BYTE> decrypted = encryptedData;
        for (size_t i = 0; i < decrypted.size(); i++) {
            decrypted[i] ^= key[i % key.size()];
            decrypted[i] ^= iv[i % iv.size()];
        }
        return decrypted;
    }
};

class PELoader {
private:
    BYTE* imageBase;
    PIMAGE_NT_HEADERS ntHeaders;

    void RedirectConsoleIO() {
        // 기존 콘솔이 있는지 확인
        HWND consoleWnd = GetConsoleWindow();
        if (consoleWnd == NULL) {
            if (!AllocConsole()) {
                return;
            }
        }

        // 표준 출력 리다이렉션
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hStdOut != INVALID_HANDLE_VALUE) {
            int hConHandle = _open_osfhandle(reinterpret_cast<intptr_t>(hStdOut), _O_TEXT);
            if (hConHandle != -1) {
                FILE* fp = _fdopen(hConHandle, "w");
                if (fp != NULL) {
                    *stdout = *fp;
                    setvbuf(stdout, NULL, _IONBF, 0);
                }
            }
        }

        // 표준 입력 리다이렉션
        HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
        if (hStdIn != INVALID_HANDLE_VALUE) {
            int hConHandle = _open_osfhandle(reinterpret_cast<intptr_t>(hStdIn), _O_TEXT);
            if (hConHandle != -1) {
                FILE* fp = _fdopen(hConHandle, "r");
                if (fp != NULL) {
                    *stdin = *fp;
                    setvbuf(stdin, NULL, _IONBF, 0);
                }
            }
        }

        // 표준 에러 리다이렉션
        HANDLE hStdErr = GetStdHandle(STD_ERROR_HANDLE);
        if (hStdErr != INVALID_HANDLE_VALUE) {
            int hConHandle = _open_osfhandle(reinterpret_cast<intptr_t>(hStdErr), _O_TEXT);
            if (hConHandle != -1) {
                FILE* fp = _fdopen(hConHandle, "w");
                if (fp != NULL) {
                    *stderr = *fp;
                    setvbuf(stderr, NULL, _IONBF, 0);
                }
            }
        }

        std::ios::sync_with_stdio(true);
    }

    bool ValidatePEStructure(const std::vector<BYTE>& data) {
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::cout << "File too small for DOS header" << std::endl;
            return false;
        }

        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cout << "Invalid DOS signature: 0x" << std::hex << dosHeader->e_magic << std::endl;
            return false;
        }

        if (dosHeader->e_lfanew < 0 ||
            static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > data.size()) {
            std::cout << "Invalid NT header offset" << std::endl;
            return false;
        }

        const IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            data.data() + dosHeader->e_lfanew);
        if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
            std::cout << "Invalid NT signature: 0x" << std::hex << ntHeader->Signature << std::endl;
            return false;
        }

        if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) {
            std::cout << ".NET assemblies are not supported" << std::endl;
            return false;
        }

        return true;
    }

    bool MapSections(const std::vector<BYTE>& peData) {
        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(peData.data());
        ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            const_cast<BYTE*>(peData.data()) + dosHeader->e_lfanew);

        imageBase = static_cast<BYTE*>(VirtualAlloc(
            NULL,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        ));

        if (!imageBase) {
            DWORD error = GetLastError();
            std::cout << "Failed to allocate memory for PE image. Error: " << error << std::endl;
            return false;
        }

        // PE 헤더 복사
        memcpy(imageBase, peData.data(), ntHeaders->OptionalHeader.SizeOfHeaders);

        // 섹션 매핑
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData > 0 &&
                sectionHeader[i].PointerToRawData < peData.size() &&
                sectionHeader[i].VirtualAddress < ntHeaders->OptionalHeader.SizeOfImage) {

                size_t copySize = min(sectionHeader[i].SizeOfRawData,
                    static_cast<DWORD>(peData.size() - sectionHeader[i].PointerToRawData));

                memcpy(
                    imageBase + sectionHeader[i].VirtualAddress,
                    peData.data() + sectionHeader[i].PointerToRawData,
                    copySize
                );
            }
        }

        return true;
    }

    bool ProcessRelocations() {
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->VirtualAddress == 0 || relocDir->Size == 0) {
            return true;
        }

        DWORD_PTR delta = reinterpret_cast<DWORD_PTR>(imageBase) - ntHeaders->OptionalHeader.ImageBase;
        if (delta == 0) {
            return true;
        }

        PIMAGE_BASE_RELOCATION relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            imageBase + relocDir->VirtualAddress);

        DWORD processedSize = 0;
        while (processedSize < relocDir->Size && relocation->VirtualAddress != 0) {
            DWORD entriesCount = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD entries = reinterpret_cast<PWORD>(
                reinterpret_cast<BYTE*>(relocation) + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < entriesCount; i++) {
                WORD entry = entries[i];
                WORD type = entry >> 12;
                WORD offset = entry & 0xFFF;

                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD* patchAddr = reinterpret_cast<DWORD*>(
                        imageBase + relocation->VirtualAddress + offset);
                    *patchAddr += static_cast<DWORD>(delta);
                }
                else if (type == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* patchAddr = reinterpret_cast<DWORD_PTR*>(
                        imageBase + relocation->VirtualAddress + offset);
                    *patchAddr += delta;
                }
            }

            processedSize += relocation->SizeOfBlock;
            relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<BYTE*>(relocation) + relocation->SizeOfBlock);
        }

        return true;
    }

    bool ResolveImports() {
        PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->VirtualAddress == 0 || importDir->Size == 0) {
            return true;
        }

        PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            imageBase + importDir->VirtualAddress);

        while (importDesc->Name != 0) {
            char* dllName = reinterpret_cast<char*>(imageBase + importDesc->Name);
            HMODULE hModule = LoadLibraryA(dllName);

            if (!hModule) {
                std::cout << "Failed to load library: " << dllName << std::endl;
                return false;
            }

            PIMAGE_THUNK_DATA thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                imageBase + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = importDesc->OriginalFirstThunk ?
                reinterpret_cast<PIMAGE_THUNK_DATA>(imageBase + importDesc->OriginalFirstThunk) : thunk;

            while (origThunk->u1.AddressOfData != 0) {
                FARPROC funcAddr = NULL;

                if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                    funcAddr = GetProcAddress(hModule,
                        reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(origThunk->u1.Ordinal)));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        imageBase + origThunk->u1.AddressOfData);
                    funcAddr = GetProcAddress(hModule, importByName->Name);
                }

                if (!funcAddr) {
                    std::cout << "Failed to resolve import from " << dllName << std::endl;
                    return false;
                }

                thunk->u1.Function = reinterpret_cast<ULONG_PTR>(funcAddr);
                thunk++;
                origThunk++;
            }

            importDesc++;
        }

        return true;
    }

public:
    PELoader() : imageBase(nullptr), ntHeaders(nullptr) {}

    bool LoadPE(const std::vector<BYTE>& peData) {
        if (!ValidatePEStructure(peData)) {
            return false;
        }

        RedirectConsoleIO();

        if (!MapSections(peData)) {
            return false;
        }

        if (!ProcessRelocations()) {
            return false;
        }

        if (!ResolveImports()) {
            return false;
        }

        return true;
    }

    bool ExecutePE() {
        if (!imageBase || !ntHeaders) {
            return false;
        }

        DWORD_PTR entryPoint = reinterpret_cast<DWORD_PTR>(imageBase) +
            ntHeaders->OptionalHeader.AddressOfEntryPoint;

        std::cout << "Executing PE at entry point: 0x" << std::hex << entryPoint << std::endl;

        if (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
            typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE, DWORD, LPVOID);
            DllEntryProc dllEntry = reinterpret_cast<DllEntryProc>(entryPoint);
            return dllEntry(reinterpret_cast<HINSTANCE>(imageBase), DLL_PROCESS_ATTACH, NULL);
        }
        else {
            typedef int(*ExeEntryProc)();
            ExeEntryProc exeEntry = reinterpret_cast<ExeEntryProc>(entryPoint);

            __try {
                int result = exeEntry();
                std::cout << "PE execution completed with result: " << result << std::endl;
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                std::cout << "Exception occurred during PE execution: 0x" <<
                    std::hex << GetExceptionCode() << std::endl;
                return false;
            }
        }
    }

    ~PELoader() {
        if (imageBase) {
            VirtualFree(imageBase, 0, MEM_RELEASE);
        }
    }
};

class AdvancedLoader {
private:
    SimpleCrypto crypto;
    PELoader peLoader;

    std::vector<BYTE> LoadEncryptedFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            std::cout << "Failed to open file: " << filename << std::endl;
            return {};
        }

        std::vector<BYTE> data((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
        file.close();

        return data;
    }

    void PrintHexDump(const std::vector<BYTE>& data, size_t maxBytes = 64) {
        std::cout << "Hex dump (first " << maxBytes << " bytes):" << std::endl;
        size_t dumpSize = (std::min)(data.size(), maxBytes);

        for (size_t i = 0; i < dumpSize; i++) {
            if (i % 16 == 0) {
                std::cout << std::hex << std::setfill('0') << std::setw(8) << i << ": ";
            }
            std::cout << std::hex << std::setfill('0') << std::setw(2) <<
                static_cast<unsigned int>(data[i]) << " ";
            if ((i + 1) % 16 == 0) {
                std::cout << std::endl;
            }
        }
        if (dumpSize % 16 != 0) {
            std::cout << std::endl;
        }
    }

public:
    bool LoadAndExecute(const std::string& filename) {
        std::cout << "Loading encrypted file: " << filename << std::endl;

        std::vector<BYTE> encryptedData = LoadEncryptedFile(filename);
        if (encryptedData.empty()) {
            return false;
        }

        std::cout << "Encrypted data size: " << encryptedData.size() << " bytes" << std::endl;
        PrintHexDump(encryptedData);

        std::cout << "Decrypting data..." << std::endl;
        std::vector<BYTE> decryptedData = crypto.Decrypt(encryptedData);

        std::cout << "Decrypted data size: " << decryptedData.size() << " bytes" << std::endl;
        PrintHexDump(decryptedData);

        std::cout << "Loading PE into memory..." << std::endl;
        if (!peLoader.LoadPE(decryptedData)) {
            std::cout << "Failed to load PE" << std::endl;
            return false;
        }

        std::cout << "Executing PE..." << std::endl;
        if (!peLoader.ExecutePE()) {
            std::cout << "Failed to execute PE" << std::endl;
            return false;
        }

        return true;
    }
};

int main() {
    try {
        AdvancedLoader loader;

        std::string filename;
        std::cout << "Enter encrypted PE file path: ";
        std::getline(std::cin, filename);

        if (loader.LoadAndExecute(filename)) {
            std::cout << "PE execution completed successfully!" << std::endl;
        }
        else {
            std::cout << "PE execution failed!" << std::endl;
        }

        std::cout << "Press Enter to exit...";
        std::cin.get();

    }
    catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }

    return 0;
}
