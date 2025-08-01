// Decompiled with JetBrains decompiler
// Type: LockBIT.KeyGenerator
// Assembly: NeonGPT, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 3B7314DB-352E-40CA-8FA8-E49938AA8847
// Assembly location: C:\Users\Desktop\Desktop\dont_scan\apps\lockbit.exe

using System.Security.Cryptography;
using System.Text;

#nullable disable
namespace LockBIT;

public class KeyGenerator
{
  public static string GetUniqueKey(int maxSize)
  {
    char[] charArray = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
    byte[] data = new byte[1];
    using (RNGCryptoServiceProvider cryptoServiceProvider = new RNGCryptoServiceProvider())
    {
      cryptoServiceProvider.GetNonZeroBytes(data);
      data = new byte[maxSize];
      cryptoServiceProvider.GetNonZeroBytes(data);
    }
    StringBuilder stringBuilder = new StringBuilder(maxSize);
    foreach (byte num in data)
      stringBuilder.Append(charArray[(int) num % charArray.Length]);
    return stringBuilder.ToString();
  }
}
