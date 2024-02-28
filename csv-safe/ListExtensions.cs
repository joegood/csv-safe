using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace csv_safe;

internal static class ListExtensions
{
    public static List<ColumnRemapping> Clone(this List<ColumnRemapping> listToClone)
    {
        var clone = new List<ColumnRemapping>();
        if (listToClone == null || listToClone.Count == 0) return clone;

        foreach (var item in listToClone)
        {
            if (item is ICloneable cloneableItem)
            {
                clone.Add((ColumnRemapping)cloneableItem.Clone());
            }
            else
            {
                // Handle the case where an item does not support cloning.
                // This might involve throwing an exception or implementing some other logic.
                throw new InvalidOperationException("Item does not support cloning.");
            }
        }
        return clone;
    }

    public static void CheckAdd(this List<ColumnRemapping> list, ColumnRemapping item)
    {
        if (list == null || item == null) return;

        if (!list.Any(c => string.Equals(c.OutputColumnName, item.OutputColumnName, StringComparison.OrdinalIgnoreCase)))
            list.Add(item);
    }
}
