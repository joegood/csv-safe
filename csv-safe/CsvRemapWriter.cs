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
    public CsvRemapWriter(CsvWriter csvWriter, List<ColumnRemapping> mappings)
    {
        CsvWriter = csvWriter;
        NewColumnMappings = mappings.Clone(); // I want to be able to change this internally w/out affecting the original.
        SafetyCheckColumnMappings();

        // We add two custom mappings to help manage the encryption
        // SAFE_META and CRYPTOHASH
        NewColumnMappings.CheckAdd(new ColumnRemapping
        {
            InputColumnName = "SAFE_META",
            OutputColumnName = "SAFE_META"
        });

        NewColumnMappings.CheckAdd(new ColumnRemapping
        {
            InputColumnName = "CRYPTOHASH",
            OutputColumnName = "CRYPTOHASH"
        });
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

    internal void WriteHeader()
    {
        // NewColumnMapping is in the order that we expect.
        foreach (var column in NewColumnMappings)
            CsvWriter.WriteField(column.OutputColumnName);

        // TODO: Encrypt the encryptable headers
    }

    internal bool WriteRecord(dynamic row)
    {
        if (row == null) return false;
        var rowDict = row as IDictionary<string, object> ?? new Dictionary<string, object>();
        if (rowDict.IsEmpty()) return false; // If the row is empty, then we will not write it to the output file.

        // NewColumnMappings has all of the expected headers, in order, that the output file will have.
        // There are some hard-coded fields that were added, "SAFE_META" and "CRYPTOHASH"
        // It is undertermined yet what SAFE:ELEMENTS will be, but it will be added here.  I anticipate it will hold structure information so the file can be reassembled during the decryption process.
        // CRYPTOHASH is a MD5 hash of the original values of the encrypted fields.  This is to verify that the data is intact after decryption.

        // Build the input string for the cryptohash.
        var cryptoHashValues = new StringBuilder();
        foreach (var column in NewColumnMappings)
        {
            if ((column.OutputColumnName ?? "").StartsWith("SAFE:"))
            {
                var value = ((rowDict.TryGetValue(column.InputColumnName.ToUpper(), out object? _value) ? _value : null) ?? "").ToString() ?? "";
                cryptoHashValues.Append(value.Trim());
            }
        }

        // Add the cryptohash to the row.
        rowDict["CRYPTOHASH"] = Cryptonator.HashMD5(cryptoHashValues.ToString());
        rowDict["SAFE_META"] = "SAFE:ELEMENTS"; // TODO: Add the structure information here.

        // NOTE:  There was a configuration option in the CsvReader [PrepareHeaderForMatch = args => args.Header.ToUpper()] that
        // defines the format of the header when is is read into the the dynamic row object.  The original casing was kept in the mappings.

        // The output columns ar already mapped.  The InputColumnName is the key to the dictionary.
        // CSVs do not have a concept of a null column, so we will write an empty string if the column is not found.

        foreach (var column in NewColumnMappings)
        {
            var value = rowDict.TryGetValue(column.InputColumnName.ToUpper(), out object? _value) ? _value : string.Empty;
            CsvWriter.WriteField(value);
        }

        return true;
    }
}
