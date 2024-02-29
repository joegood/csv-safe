using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using CsvHelper.Configuration;
using CsvHelper;
using System.Dynamic;
using System.Globalization;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Diagnostics;


namespace csv_safe;

/*
Application Name: csv-safe
Purpose:  To allow a user to encrypt a selected subset of fields/columns in a CSV file, allowing the file
to be read or manipulated by a third party, then unencrypted when the file is returned.

Requirements:
1. C#, .Net 8
2. Command-Line / Console Application
3. Accepts command like parameters:  csv-safe.exe input_file.csv (-e|-d|--encrypt|--decrypt) password [-o output_file.csv] [(-c|--columns) col1,"col2","col2,again",col3]
   -e or --encrypt triggers encryption mode
   -d or --decrypt triggers decryption mode
   encryption and decryption are mutually exclusive.
   either encryption or decryption is required
   password is required
   -o specifies the output file.  This is optional.  If output is omitted, ouptut is inferred by the input name but appends "safe" to the name.
   -c or --columns presents a list of columns, comma-seperated, with optional double-quotes to allow spaces or commas.
   columns is required when encrypting and not used when decrypting.
4. Can work with CSV files greater than the RAM of the machine.  
5. Uses the library CsvHelper, installed with "dotnet add package CsvHelper"
6. The encryption function uses a salt of "XYZZY"
7. The encryption algorithm is AES-128
8. The column names will be encrypted as well.  Prior to encryption, the column name is changed to "SAFE:{NAME}".
9. When the CSV file is decrypted, every column header name has a decryption attempt on it.  If a column is successfully decrypted and the resulting name begins with "SAFE:", we know that column was a column originally encrypted by this user and valid for decryption.
*/


internal class Program
{
    // Private static field of type CsvConfiguration
    private static readonly CsvConfiguration config = new CsvConfiguration(System.Globalization.CultureInfo.InvariantCulture)
    {
        // Configuration to ensure we can handle various CSV formats and nuances.
        PrepareHeaderForMatch = args => args.Header.ToUpper(),
        IgnoreBlankLines = true,
        TrimOptions = TrimOptions.Trim,
        HasHeaderRecord = true,
        Delimiter = ",",
        Quote = '"',
        AllowComments = true,
        CacheFields = true,
        Comment = '#'
    };

    private static void RunCsvHelperExperiment()
    {
        var records = new List<dynamic>();

        dynamic record = new ExpandoObject();
        record.Id = 1;
        record.Name = "one";
        records.Add(record);
        record = new ExpandoObject();
        record.Id = 2;
        record.Name = "TWO";
        records.Add(record);
        record = new ExpandoObject();
        record.Id = 3;
        record.Name = "THREE";
        record.Extra = "This is extra data.";
        records.Add(record);

        using (var writer = new StreamWriter("xyzzy.csv"))
        using (var csv = new CsvWriter(writer, config))
        {
            // .WriteEncryptedRecord against a List<dynamic> works, but they're all in memory.
            // csv.WriteRecords(records);
            csv.WriteDynamicHeader(records[0]);
            csv.NextRecord();
            foreach (var rec in records)
            {
                csv.WriteRecord(rec);
                csv.NextRecord();
            }
            writer.Flush();
        }

    }

    static void Main(string[] args)
    {
        try
        {
            var options = new CommandLineOptions(args);

            if (options.IsEncryptMode)
            {
                DoEncryptFile(options.InputFile, options.OutputFile, options.Password, options.Columns);
            }
            else if (options.IsDecryptMode)
            {
                DoDecryptFile(options.InputFile, options.OutputFile, options.Password);
            }
        }
        catch (Exception ex)
        {
            ReportException(ex);
        }
    }

    private static void ReportException(Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.DarkRed;
        Console.BackgroundColor = ConsoleColor.White;
        var message = ex switch
        {
            ArgumentException argEx => $"Argument exception: {argEx.Message}",
            InvalidOperationException opEx => $"Invalid operation: {opEx.Message}",
            NullReferenceException nullRefEx => $"Null reference: {nullRefEx.Message}",

            // Add patterns for other specific exception types as needed

            _ => $"Unknown exception type: {ex.Message}" // Default case for exceptions not specifically handled
        };

        Console.WriteLine("Error: ".PadRight(Console.WindowWidth - 1));
        Console.WriteLine(message.PadRight(Console.WindowWidth - 1));

        // Check if a debugger is attached.  If so, output the method and line number of the exception.
        if (Debugger.IsAttached)
        {
            var st = new StackTrace(ex, true);
            var frame = st.GetFrame(0); // Get the top frame
            if (frame != null)
            {
                var method = frame.GetMethod();
                var fileName = frame.GetFileName();
                var lineNumber = frame.GetFileLineNumber();

                Console.BackgroundColor = ConsoleColor.Gray;
                // Output the information about the offending function
                Console.WriteLine($"Offending method: {method?.DeclaringType?.FullName}.{method?.Name}");
                if (!string.IsNullOrEmpty(fileName) && lineNumber != 0)
                {
                    Console.WriteLine($"File: {fileName}, Line: {lineNumber}");
                }
            }
        }

        Console.ResetColor();
    }

    private static void DoEncryptFile(string inputFile, string outputFile, string password, List<string> argColumns)
    {
        /* Initial processing of header row to determine which columns are to be encrypted.
         * The column list is human-entered and may not match the actual column names in the file.
         * For each column in list, scan the header row for a match. If no match, print a yellow warning message that the column was not found.
         * For each column that matches, the header name is changed to "SAFE:INDEX:NAME" where INDEX is the 0-based index of the column and NAME is the original column name.
         * Each matched column is then moved to the end of the column list.  They maintain the order in which they are found in the file.
         * A mapping is made of the original column name to the new column name.
         * Once the mapping is made of the original column, is is no longer needed in the output file.
         * A new column is added end of the column list namded "CRYPTOHASH".  This column will contain the MD5 hash of the encrypted fields in the row.
         * All crypto matched columns names and the CRYPTOHASH column are then encrypted.
         * As each row is read, the matched columns are encrypted, the resulting fields at the end of the row are updated with the values and the CRYPTOHASH is updated with the MD5 hash of the encrypted fields.
         * The row is then written to the output file.
         */

        var encryptedColumns = new List<ColumnRemapping>();
        var regularColumns = new List<ColumnRemapping>();
        var foundColumns = new List<string>();

        using (var reader = new StreamReader(inputFile))
        using (var csvReader = new CsvReader(reader, config))
        {
            csvReader.Read();
            csvReader.ReadHeader();
            var headerRecord = csvReader.HeaderRecord;

            // Initial processing of header row to determine columns to be encrypted
            int index = 0;
            foreach (var _header in headerRecord)
            {
                var header = _header.Trim();

                // Blank headers are problematic.  Even in the most flexible format, using dynamic objects, since the header is used as a property name, you can have only one empty header.
                // But even that is problematic.  So I'm going to just call it and require that all fields have a header.

                if (string.IsNullOrWhiteSpace(header)) throw new InvalidOperationException("All columns must have a header name.");

                if (argColumns.Any(c => string.Equals(c, header, StringComparison.OrdinalIgnoreCase)))
                {
                    var encryptedHeaderName = $"SAFE:{index}:{header}";
                    encryptedColumns.Add(new ColumnRemapping { InputColumnName = header, InputColumnIndex = index, OutputColumnName = encryptedHeaderName });
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(header)) header = $"FIELD_{index}"; // If the header is empty, we will use a default name.
                    regularColumns.Add(new ColumnRemapping { InputColumnName = header, InputColumnIndex = index, OutputColumnName = header });
                }
                foundColumns.Add(header);
                index++;
            }
        }

        // Warn about columns not found
        Console.ForegroundColor = ConsoleColor.Yellow;
        foreach (var column in argColumns.Where(c => !foundColumns.Any(k => string.Equals(k, c, StringComparison.OrdinalIgnoreCase))))
            Console.WriteLine($"Warning: Column '{column}' not found, will be ignored.");
        Console.ResetColor();

        // At the end of the previous loop, there are four collections:
        //   encryptedColumns: The set of columns that are remapped to encrypted names
        //   regularColumns:   The set of columns that remain unchanged

        // To accomplish the reordering and maping of field names, I am passing this off to a custom CsvRemapWriter class.
        // TODO:  Decide if CsvRemapWriter just extends CsvWriter or if it is a separate class that takes a CsvWriter as a parameter.

        // Build the mapping list.
        var newColumnMapping = new List<ColumnRemapping>();
        var rindex = 0;
        foreach (var column in regularColumns)
        {
            column.OutputColumnIndex = rindex;
            newColumnMapping.Add(column);
            rindex++;
        }
        foreach (var column in encryptedColumns)
        {
            column.OutputColumnIndex = rindex;
            column.IsValueEncrypted = true;
            column.IsHeaderEncrypted = true;
            newColumnMapping.Add(column);
            rindex++;
        }


        using (var reader = new StreamReader(inputFile))
        using (var writer = new StreamWriter(outputFile))
        using (var csvReader = new CsvReader(reader, config))
        using (var csvWriter = new CsvWriter(writer, config))
        {
            // This has to handle millions of rows, far beyond what can fit in memory...
            // So we'll have to read and write one row at a time.

            // The output CSV needs to have the original column names replaced with the encrypted column names
            // As we read row by row, values from the reader are written to the writer using the encrypted column names.

            var remapWriter = new CsvRemapWriter(csvWriter, newColumnMapping, password, addEncryptingMetadata: true);

            // Write the new header to the output file
            remapWriter.WriteEncryptedHeader();
            csvWriter.NextRecord();

            var count = 0;
            // Process each row
            while (csvReader.Read())
            {
                // Since we do not know what the CSV file contains, we will use a dynamic object to read the row.

                // Blank headers are problematic.  Even in the most flexible format, using dynamic objects, since the header is used as a property name, you can have only one empty header.
                // Higher up, an exception is raised if blank or empty headers are found.  So we should not have to worry about that here.

                var row = csvReader.GetRecord<dynamic>();
                if (row == null) continue;

                if (remapWriter.WriteEncryptedRecord(row))
                    csvWriter.NextRecord();

                count++;
                if (count % 10000 == 0) Console.WriteLine($"{count}");

            } // while read

        } // usings

    } // DoEncryptFile


    private static void DoDecryptFile(string inputFile, string outputFile, string password)
    {
        /* The first attempt will be to just reverse the logic in the DoEncryptFile method.
         * The header row is read and the column names are decrypted.
         * From the header row, a mapping is made of the original column name to the new column name.
         * The header row is written to the output file.
         * Each row is read and the encrypted columns are decrypted.
         * The row is written to the output file.
         */

        var foundColumns = new List<ColumnRemapping>();
        var toBeMovedColumns = new List<ColumnRemapping>();
        ColumnRemapping? cryptoHashMapping = null;

        using (var reader = new StreamReader(inputFile))
        using (var csvReader = new CsvReader(reader, config))
        {
            csvReader.Read();
            csvReader.ReadHeader();
            var headerRecord = csvReader.HeaderRecord;

            // Initial processing of header row to determine columns to be to be decrypted and rearranged
            int index = 0;
            foreach (var _header in headerRecord)
            {
                var header = _header.Trim();

                // Blank headers are problematic.  Even in the most flexible format, using dynamic objects, since the header is used as a property name, you can have only one empty header.
                // But even that is problematic.  So I'm going to just call it and require that all fields have a header.

                if (string.IsNullOrWhiteSpace(header)) throw new InvalidOperationException("All columns must have a header name.");

                // Every header will be decrypted.  If the header is a valid encrypted header, it will begin with "SAFE:" or be "CRYPTOHASH".
                // If the header does not decrypt (due to padding issues, etc.), or not match the above patterns, it will be left as is.
                // Currently, all special encryption related fields are moved to the end.  There is no guarantee that they will be in the same order as the file is manipulated by a third party.

                if (Cryptonator.TryUnmaskStringFromHex(header, password, out var _decryptedHeader))
                    if (_decryptedHeader != null)
                    {
                        // It was the correct shape to decrypt, now to see if it actually did decrypt propertly.
                        string decryptedHeader = (_decryptedHeader ?? "");

                        // Every successful identification of an encrypted field will trigger a continue of the for loop to jump to the next field

                        if (decryptedHeader.StartsWith("SAFE:"))
                        {
                            var parts = decryptedHeader.Split(':');
                            if (parts.Length == 3 && int.TryParse(parts[1], out var indexValue))
                            {
                                toBeMovedColumns.Add(new ColumnRemapping { InputColumnName = header, InputColumnIndex = index, OutputColumnName = parts[2], OutputColumnIndex = indexValue, IsValueEncrypted = true, IsHeaderEncrypted = true });
                                index++;
                                continue;
                            }
                        }
                        else if (decryptedHeader == "CRYPTOHASH")
                        {
                            cryptoHashMapping = new ColumnRemapping { InputColumnName = header, InputColumnIndex = index, OutputColumnName = "CRYPTOHASH", OutputColumnIndex = index, IsValueEncrypted = false, IsHeaderEncrypted = true, IncludeInOutput = false };
                            index++;
                            continue;
                        }
                    } // if decrypted

                // Either it wasn't decrypted or it wasn't a valid encrypted header.  Either way, it's a regular column.
                foundColumns.Add(new ColumnRemapping { InputColumnName = header, InputColumnIndex = index, OutputColumnName = header, OutputColumnIndex = index, IsValueEncrypted = false, IsHeaderEncrypted = false });
                index++;

            } // foreach header
        } // using reader

        // The foundColumns list now contains a mapping of the original column name to the new column name, but it is not in the order that we want.
        // The index here was determined by the order discovered in the file. But the encrypted fields contained their original index, so we insert them back into the list in the correct order.
        // We need to start with the lowest index and work our way up.

        foreach (var colToMove in toBeMovedColumns.OrderBy(c => c.OutputColumnIndex))
            foundColumns.Insert(colToMove.OutputColumnIndex, colToMove);

        // Now that the columns are physically in the correct order, go back and reset the OutputColumnIndex to match.
        var sindex = 0;
        foreach (var column in foundColumns)
            column.OutputColumnIndex = sindex++;  // sindex 😈 🤘


        using (var reader = new StreamReader(inputFile))
        using (var writer = new StreamWriter(outputFile))
        using (var csvReader = new CsvReader(reader, config))
        using (var csvWriter = new CsvWriter(writer, config))
        {

            var remapWriter = new CsvRemapWriter(csvWriter, foundColumns, password, addDecryptingMetadata: cryptoHashMapping != null); // only add the decrypt metadata if there is a crypto hash mapping

            // Prototype this out to make sure we get the columns put back into the correct order first

            // Write the new header to the output file
            // Headers were already decrypted above.. so the OutputColumnName is the correct name.
            remapWriter.WriteHeader();
            csvWriter.NextRecord();

            var count = 0;
            // Process each row
            while (csvReader.Read())
            {
                // Since we do not know what the CSV file contains, we will use a dynamic object to read the row.

                // Just like with the encryption loop, blank headers are problematic.
                // Higher up, an exception is raised if blank or empty headers are found.

                var row = csvReader.GetRecord<dynamic>();
                if (row == null) continue;

                // Unlike the encryption loop, we need to check the hash if it is present
                string? rowhash = null;
                if (cryptoHashMapping != null)
                {
                    // Get the stored hash from the row and put it in the rowhash variable
                    rowhash = (row as IDictionary<string,object>)?.SafeToString(cryptoHashMapping.InputColumnName);
                }

                bool hashMatch = false;

                if (remapWriter.WriteDecryptedRecord(row, rowhash, out hashMatch))
                    csvWriter.NextRecord();

                count++;
                if (count % 10000 == 0) Console.WriteLine($"{count}");


            } // while read

        } // usings
    } // DoDecryptFile
}
