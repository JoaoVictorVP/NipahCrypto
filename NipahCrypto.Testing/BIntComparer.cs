using System.Numerics;

struct BIntComparer : IComparer<BigInteger>
{
    public int Compare(BigInteger x, BigInteger y) => BigInteger.Compare(x, y);
}
