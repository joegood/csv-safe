using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace csv_safe;

internal class Cryptonator
{
    private const int SALT_BYTES_SIZE = 4;  // A small salt.. but we don't need to be super-secure here
    private const int KEY_ITERATIONS = 3; // For real encryption, this should be very high but for this purpose, it's fine. We need volume.

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
        if (string.IsNullOrWhiteSpace(password)) return string.Empty;

        // We want to allow empty values to be encrypted, but trimmed, because having a blank could be giving away info about the data.
        // Example, if the field was "PassedHeartScreenCheck" and the value was "", then we know that the person did not pass the check.
        // I know the header name is also encrypted but in case the header name is decrypted or inferred, we still do not want access to free info.

        value = (value ?? "").Trim();

        byte[] encryptedBytes;
        byte[] salt = new byte[SALT_BYTES_SIZE];
        using (var rng = RandomNumberGenerator.Create())
            rng.GetBytes(salt); // Generate a secure random salt

        using (Aes aesAlg = Aes.Create())
        {
            var pdb = new Rfc2898DeriveBytes(password, salt, KEY_ITERATIONS, HashAlgorithmName.SHA256);
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
            var pdb = new Rfc2898DeriveBytes(password, salt, KEY_ITERATIONS, HashAlgorithmName.SHA256);
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

    internal static bool TryDecryptAES(string value, string password, out string? decrypted)
    {
        try
        {
            decrypted = DecryptAES(value, password);
            return true;
        }
        catch (Exception)
        {
            decrypted = null;
            return false;
        }
    }

    internal static string Encrypt(string value, string password) => EncryptAES(value, password);

    internal static string Decrypt(string value, string password) => DecryptAES(value, password);

    internal static bool TryDecrypt(string value, string password, out string? decrypted) => TryDecryptAES(value, password, out decrypted);

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

    public static string MaskStringAsHex(string value, string mask)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (string.IsNullOrEmpty(mask)) mask = value;

        while (mask.Length < value.Length) { mask += mask; }
        mask = mask[..value.Length]; // make them both the same length

        // Generate a random hex digit
        Random rnd = new();
        byte salt = (byte)rnd.Next(0, 16); // 0x00 to 0x0F

        // Convert strings and salt to byte arrays
        byte[] valueBytes = Encoding.UTF8.GetBytes(value);
        byte[] maskBytes = Encoding.UTF8.GetBytes(mask);

        // Perform XOR operation with value and mask, then with salt
        byte[] resultBytes = new byte[valueBytes.Length];
        for (int i = 0; i < valueBytes.Length; i++)
        {
            resultBytes[i] = (byte)(valueBytes[i] ^ maskBytes[i] ^ salt); // xor with mask then salt
        }

        // Convert the bytes to a hex string and prepend the salt
        return salt.ToString("X") + Convert.ToHexString(resultBytes);
    }

    public static string UnmaskStringFromHex(string value, string mask)
    {
        if (string.IsNullOrEmpty(value)) return "";
        ArgumentException.ThrowIfNullOrEmpty(mask, nameof(mask));

        // If this doesn't have a salt digit, then it isn't a masked string.
        // Not saying that it is a masked string, but this is one way to quickly filter out non-masked strings.
        var c_salt = (char)value[0];
        if (c_salt < '0' || (c_salt > '9' && c_salt < 'A') || c_salt > 'F') return "";

        // Extract salt digit from the value
        byte salt = Convert.ToByte(value[..1], 16);
        value = value[1..]; // Remove the salt digit from the value

        // If the value is not a multiple of 2, it is not a valid hex string..
        if (value.Length % 2 != 0) return "";

        byte[] valueBytes = Convert.FromHexString(value);

        while (mask.Length < valueBytes.Length) { mask += mask; }
        mask = mask[..valueBytes.Length]; // make them both the same length
        byte[] maskBytes = Encoding.UTF8.GetBytes(mask);

        // Perform XOR operation with salt and then mask
        byte[] resultBytes = new byte[valueBytes.Length];
        for (int i = 0; i < valueBytes.Length; i++)
        {
            resultBytes[i] = (byte)(valueBytes[i] ^ salt ^ maskBytes[i]); // xor with salt then mask
        }

        // Convert the bytes back to a regular string
        return Encoding.UTF8.GetString(resultBytes);
    }


    public static bool TryUnmaskStringFromHex(string value, string mask, out string? unmasked)
    {
        try
        {
            unmasked = UnmaskStringFromHex(value, mask);
            return true;
        }
        catch (Exception)
        {
            unmasked = null;
            return false;
        }
    }   

}
