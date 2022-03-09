using NipahCrypto.Core;

namespace SPHINCSPlus;

public unsafe struct address
{
    public fixed uint values[8];

    public static implicit operator address(uint[] values)
    {
        address r;
        values.AssertLength(8);
        for (int i = 0; i < 8; i++)
            r.values[i] = values[i];

        return r;
    }
}