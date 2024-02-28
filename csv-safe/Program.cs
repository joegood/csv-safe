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
            // .WriteRecord against a List<dynamic> works, but they're all in memory.
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

        Console.WriteLine("Error: ".PadRight(Console.WindowWidth));
        Console.WriteLine(message.PadRight(Console.WindowWidth));

        Console.ResetColor();
    }

    private static void DoEncryptFile(string inputFile, string outputFile, string password, List<string> argColumns)
    {
        /* Initial processing of header row to determine which columns are to be encrypted.
         * All encryption is AES-128 with a salt of "XYZZY"
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
        using (var csvReader = new CsvReader(reader, new CsvConfiguration(System.Globalization.CultureInfo.InvariantCulture) { PrepareHeaderForMatch = args => args.Header.ToLower() }))
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

            var remapWriter = new CsvRemapWriter(csvWriter, newColumnMapping);

            // Write the new header to the output file
            remapWriter.WriteHeader();
            csvWriter.NextRecord();

            // Process each row
            while (csvReader.Read())
            {
                // Since we do not know what the CSV file contains, we will use a dynamic object to read the row.

                // Blank headers are problematic.  Even in the most flexible format, using dynamic objects, since the header is used as a property name, you can have only one empty header.
                // Higher up, an exception is raised if blank or empty headers are found.  So we should not have to worry about that here.

                var row = csvReader.GetRecord<dynamic>();
                if (row == null) continue;

                if (remapWriter.WriteRecord(row))
                    csvWriter.NextRecord();

            } // while read

        } // usings

    } // DoEncryptFile


    private static void DoDecryptFile(string inputFile, string outputFile, string password)
    {
        throw new NotImplementedException();
    }

}
