using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace csv_safe;

public class CommandLineOptions
{
    public string InputFile { get; private set; }
    public string OutputFile { get; private set; }
    public string Password { get; private set; }
    public List<string> Columns { get; private set; }
    public bool IsEncryptMode { get; private set; }
    public bool IsDecryptMode { get; private set; }

    public CommandLineOptions(string[] args)
    {
        InputFile = "";
        OutputFile = "";
        Password = "";
        Columns = [];
        IsEncryptMode = false;
        IsDecryptMode = false;
        ParseArgs(args);
    }

    private void ParseArgs(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "-e":
                case "--encrypt":
                    IsEncryptMode = true;
                    Password = args[++i]; // Increment i to skip next argument as it is the value for -e
                    break;
                case "-d":
                case "--decrypt":
                    IsDecryptMode = true;
                    Password = args[++i];
                    break;
                case "-o":
                    OutputFile = args[++i]; // Increment i to skip next argument as it is the value for -o
                    break;
                case "-c":
                case "--columns":
                    // Split the next argument by comma and add to Columns list
                    Columns.AddRange(SplitColumns(args[++i]));
                    break;
                default:
                    if (string.IsNullOrWhiteSpace(InputFile))
                        InputFile = args[i];
                    break;
            }
        }

        if (IsEncryptMode && IsDecryptMode)
            throw new ArgumentException("Encryption and decryption modes are mutually exclusive.");

        if (string.IsNullOrWhiteSpace(InputFile) || string.IsNullOrWhiteSpace(Password))
            throw new ArgumentException("Input file and password are required.");

        if (IsEncryptMode && !Columns.Any())
            throw new ArgumentException("Columns must be specified for encryption.");

        // If OutputFile is not specified, infer it from InputFile
        if (string.IsNullOrWhiteSpace(OutputFile))
        {
            var inputSansExt = Path.GetFileNameWithoutExtension(InputFile);
            if (IsEncryptMode)
            {
                if (inputSansExt.ToLower().EndsWith("_decrypted"))
                    inputSansExt = $"{inputSansExt[..^10]}";
                OutputFile = $"{inputSansExt}_safe.csv";
            }
            else if (IsDecryptMode)
            {
                if (inputSansExt.ToLower().EndsWith("_safe"))
                    inputSansExt = $"{inputSansExt[..^5]}";
                OutputFile = $"{inputSansExt}_decrypted.csv";
            }
        }
    }

    private static readonly char[] separator = [','];

    private static IEnumerable<string> SplitColumns(string columnsArg)
    {
        return columnsArg.Split(separator, StringSplitOptions.RemoveEmptyEntries)
                         .Select(col => col.Trim('"').Trim());
    }
}
