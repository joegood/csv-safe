using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace csv_safe;

internal static class DynamicExtensions
{
    public static bool IsEmpty(this IDictionary<string, object> item)
    {
        if (item == null || item.Count == 0) return true;

        // If all of the values are null or empty, then the dictionary is empty.
        // Spaces do count in this case and are not treated as empty.

        return item.Values.All(v => v == null || string.IsNullOrEmpty(v?.ToString()));
    }

}
