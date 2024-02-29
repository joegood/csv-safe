using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace csv_safe;

internal class ColumnRemapping : ICloneable
{
    public bool IsHeaderEncrypted { get; set; } = false;
    public bool IsValueEncrypted { get; set; } = false;

    public int InputColumnIndex { get; set; } = -1;
    public int OutputColumnIndex { get; set; } = -1;

    // I am forcing the names to either have a value or be null so in other areas I can use null coalescing operator.

    public string InputColumnName { get; set; } = "";

    string? _outputColumnName;
    public string? OutputColumnName { get => _outputColumnName; set => _outputColumnName = NullForce(value); }

    private static string? NullForce(string? value) => string.IsNullOrWhiteSpace(value) ? null : value; // Like SpaceForce, but way more boring

    public object Clone()
    {
        return new ColumnRemapping
        {
            IsHeaderEncrypted = this.IsHeaderEncrypted,
            IsValueEncrypted = this.IsValueEncrypted,
            InputColumnIndex = this.InputColumnIndex,
            OutputColumnIndex = this.OutputColumnIndex,
            InputColumnName = this.InputColumnName,
            OutputColumnName = this.OutputColumnName
        };
    }
}
