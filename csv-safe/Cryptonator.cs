using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace csv_safe;

internal class Cryptonator
{
    private const int SALT_BYTES_SIZE = 4;  // A small salt.. but we don't need to be super-secure here

    internal static string HashMD5(string value)
    {
        // Generate the hash bytes and use RollBase64 to convert to a string.
        // If the string is null or empty, return "8675309" as the hash.
        if (string.IsNullOrEmpty(value)) return "8675309"; // Don't lose that number

        var hash = MD5.HashData(Encoding.UTF8.GetBytes(value));
        return RollBase64(hash);
    }

    public static string EncryptAES(string value, string password)
    {
        if (string.IsNullOrEmpty(value) || string.IsNullOrWhiteSpace(password)) return string.Empty;

        byte[] encryptedBytes;
        byte[] salt = new byte[SALT_BYTES_SIZE];
        using (var rng = RandomNumberGenerator.Create())
            rng.GetBytes(salt); // Generate a secure random salt

        using (Aes aesAlg = Aes.Create())
        {
            var pdb = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            aesAlg.Key = pdb.GetBytes(32); // AES-256
            aesAlg.IV = pdb.GetBytes(16); // AES block size is 128 bits

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using var msEncrypt = new MemoryStream();
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(value);
            }
            encryptedBytes = msEncrypt.ToArray();
        }

        // Prepend the salt to the encrypted bytes
        var encryptedDataWithSalt = new byte[salt.Length + encryptedBytes.Length];
        Buffer.BlockCopy(salt, 0, encryptedDataWithSalt, 0, salt.Length);
        Buffer.BlockCopy(encryptedBytes, 0, encryptedDataWithSalt, salt.Length, encryptedBytes.Length);

        return Convert.ToBase64String(encryptedDataWithSalt);
    }

    public static string DecryptAES(string value, string password)
    {
        if (string.IsNullOrEmpty(value) || string.IsNullOrWhiteSpace(password)) return string.Empty;

        string plaintext = "";
        var allBytes = Convert.FromBase64String(value);
        byte[] salt = new byte[SALT_BYTES_SIZE];
        byte[] encryptedBytes = new byte[allBytes.Length - salt.Length];

        // Extract salt and encrypted data
        Buffer.BlockCopy(allBytes, 0, salt, 0, salt.Length);
        Buffer.BlockCopy(allBytes, salt.Length, encryptedBytes, 0, encryptedBytes.Length);

        using (Aes aesAlg = Aes.Create())
        {
            var pdb = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            aesAlg.Key = pdb.GetBytes(32); // AES-256
            aesAlg.IV = pdb.GetBytes(16);

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using var msDecrypt = new MemoryStream(encryptedBytes);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            plaintext = srDecrypt.ReadToEnd();
        }

        return plaintext;
    }

    internal static string Encrypt(string value, string password) => EncryptAES(value, password);

    internal static string Decrypt(string value, string password) => DecryptAES(value, password);

    internal static string RollBase64(byte[] bytes)
    {
        // Return the byte array as a base64 string.  If null or empty, return an empty string.
        if (bytes == null || bytes.Length == 0) return string.Empty;
        return Convert.ToBase64String(bytes);
    }

    internal static byte[] UnrollBase64(string value)
    {
        // Convert the base64 string to a byte array.  If null or empty, return an empty byte array.
        if (string.IsNullOrEmpty(value)) return [];
        return Convert.FromBase64String(value);
    }


}
