using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NipahCrypto.Core;

public static class NAssert
{
    public static void AssertLength<T>(this IList<T> collection!!, int length)
    {
        if (collection.Count != length)
            throw new NAssertException($"Expecting length of {length}");
    }
}
