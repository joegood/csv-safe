using CsvHelper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;

namespace csv_safe;
internal class CsvRemapWriter
{
    private string Password { get; set; }

    public CsvRemapWriter(CsvWriter csvWriter, List<ColumnRemapping> mappings, string password, bool addEncryptingMetadata = false, bool addDecryptingMetadata = false)
    {
        ArgumentNullException.ThrowIfNull(csvWriter);
        ArgumentNullException.ThrowIfNull(mappings);
        if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));

        CsvWriter = csvWriter;
        Password = password;
        NewColumnMappings = mappings.Clone(); // I want to be able to change this internally w/out affecting the original.
        SafetyCheckColumnMappings();

        // We add some custom mappings to help with the decryption and reassembly process.  
        if (addEncryptingMetadata)
        {
            NewColumnMappings.CheckAdd(new ColumnRemapping
            {
                InputColumnName = "CRYPTOHASH",
                OutputColumnName = "CRYPTOHASH",
                IsHeaderEncrypted = true,
                IsValueEncrypted = false,
                IncludeInOutput = true
            });
        }

        if (addDecryptingMetadata)
        {
            NewColumnMappings.CheckAdd(new ColumnRemapping
            {
                InputColumnName = "ROWCHECK",
                OutputColumnName = "ROWCHECK",
                IsHeaderEncrypted = false,
                IsValueEncrypted = false,
                IncludeInOutput = true
            });
        }
    }

    public CsvWriter CsvWriter { get; }
    public List<ColumnRemapping> NewColumnMappings { get; }

    private void SafetyCheckColumnMappings()
    {
        // For safety, we will use an index when cycling the list and in case an output column name is not provided, we will use the input column name, else "FIELD_" + index
        // ColumnRemapping will ensure that the names are either null or have a value so we can use the null coalescing operator.

        var index = 0;
        foreach (var column in NewColumnMappings)
            column.OutputColumnName ??= column.InputColumnName ?? "FIELD_" + index++;
    }

    internal void WriteEncryptedHeader()
    {
        // Go through each column and write the header, as a field.  Instead of encrypting the headers, I'm masking them.
        // This is necessary because encrypted headers are sensitive to alterations in the case... and not all tools play nice with case.
        // Masking and using hex will still obstruct the header from being easily read, but will not be sensitive to case.
        // The real data is still encrypted.
        foreach (var column in NewColumnMappings)  // NewColumnMapping is in the order that we expect.
        {
            if (column.IsHeaderEncrypted)
                CsvWriter.WriteField(Cryptonator.MaskStringAsHex(column.OutputColumnName ?? "", this.Password));
            else
                CsvWriter.WriteField(column.OutputColumnName);
        }
    }

    internal void WriteDecryptedHeader()
    {
        // See notes in WriteEnryptedHeader()
        foreach (var column in NewColumnMappings)  // NewColumnMapping is in the order that we expect.
        {
            if (column.IsHeaderEncrypted)
                CsvWriter.WriteField(Cryptonator.UnmaskStringFromHex(column.OutputColumnName ?? "", this.Password));
            else
                CsvWriter.WriteField(column.OutputColumnName);
        }
    }

    internal void WriteHeader()
    {
        foreach (var column in NewColumnMappings)  // NewColumnMapping is in the order that we expect.
        {
            CsvWriter.WriteField(column.OutputColumnName);
        }
    }

    internal bool WriteEncryptedRecord(dynamic row)
    {
        if (row == null) return false;
        var rowDict = row as IDictionary<string, object> ?? new Dictionary<string, object>();
        if (rowDict.IsEmpty()) return false; // If the row is empty, then we will not write it to the output file.

        // NewColumnMappings has all of the expected headers, in order, that the output file will have.
        // CRYPTOHASH is a MD5 hash of the original values of the encrypted fields.  This is to verify that the data is intact after decryption.

        // Build the input string for the cryptohash.
        var cryptoHashValues = new StringBuilder();
        foreach (var column in NewColumnMappings)
        {
            if ((column.OutputColumnName ?? "").StartsWith("SAFE:"))
            {
                var value = rowDict.SafeToString(column.InputColumnName.ToUpper());  // CsvReader will have the column names in upper case.
                cryptoHashValues.Append(value.Trim());
            }
        }

        // Add the cryptohash to the row.
        rowDict["CRYPTOHASH"] = Cryptonator.HashMD5(cryptoHashValues.ToString());

        // NOTE:  There was a configuration option in the CsvReader [PrepareHeaderForMatch = args => args.Header.ToUpper()] that
        // defines the format of the header when is is read into the the dynamic row object.  The original casing was kept in the mappings.

        // The output columns ar already mapped.  The InputColumnName is the key to the dictionary.
        // CSVs do not have a concept of a null column, so we will write an empty string if the column is not found.

        foreach (var column in NewColumnMappings)
        {
            var value = rowDict.SafeToString(column.InputColumnName.ToUpper()); // CsvReader will have the column names in upper case.
            if (column.IsValueEncrypted)
                value = Cryptonator.EncryptAES(value.ToString(), this.Password);
            CsvWriter.WriteField(value);
        }

        return true;
    }

    internal bool WriteDecryptedRecord(dynamic row, string? rowhash, out bool hashMatch)
    {
        hashMatch = false;
        if (row == null) return false;
        var rowDict = row as IDictionary<string, object> ?? new Dictionary<string, object>();
        if (rowDict.IsEmpty()) return false; // If the row is empty, then we will not write it to the output file.

        // NewColumnMappings has all of the expected headers, in order, that the output file will have.
        // CRYPTOHASH is a MD5 hash of the original values of the encrypted fields.  This is to verify that the data is intact after decryption.

        // NOTE:  There was a configuration option in the CsvReader [PrepareHeaderForMatch = args => args.Header.ToUpper()] that
        // defines the format of the header when is is read into the the dynamic row object.  The original casing was kept in the mappings.

        // At this point, [row] contains masked field names and encrypted values.
        // The NewColumnMappings does contain the maps from the encrpted field names to the original field names.
        // NewColumnMappings is 

        // There is a mapping in the output fields, ROWCHECK, that was added only if a CRYPTHASH column was found.
        // But, just because one was found doesn't mean the hash was in the values.  It could have been removed.
        // We need to make sure there is a boolean value ready for it when we go through the columns and write values based on names.

        var rowCheck = "FAIL"; // assume failure

        if (!string.IsNullOrWhiteSpace(rowhash))
        {
            // Build the input string for the cryptohash.
            var cryptoHashValues = new StringBuilder();
            foreach (var column in NewColumnMappings)
                if (column.IsValueEncrypted && column.IncludeInOutput)
                {
                    var value = rowDict.SafeToString(column.InputColumnName.ToUpper());  // CsvReader will have the column names in upper case.
                    if (Cryptonator.TryDecrypt(value, this.Password, out string? decryptedValue))
                    {
                        value = decryptedValue;
                    }
                    cryptoHashValues.Append(value?.Trim() ?? "");
                }
            var foundHash = Cryptonator.HashMD5(cryptoHashValues.ToString());

            hashMatch = string.Compare(rowhash, foundHash, StringComparison.Ordinal) == 0;
            // the hashMatch will surface up at the program level so the user can be prompted to continue
            if (hashMatch) rowCheck = "PASS";
        }
        rowDict.Add("ROWCHECK", rowCheck);


        foreach (var column in NewColumnMappings)
        {
            if (!column.IncludeInOutput) continue;
            var value = rowDict.SafeToString(column.InputColumnName.ToUpper()); // CsvReader will have the column names in upper case.
            if (column.IsValueEncrypted && Cryptonator.TryDecrypt(value, this.Password, out string? decryptedValue))
            {
                value = decryptedValue;
            }

            CsvWriter.WriteField(value);
        }

        return true;
    }

}
