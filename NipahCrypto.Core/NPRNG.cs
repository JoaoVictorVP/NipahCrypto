using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace NipahCrypto.Core;

public struct NPRNG
{
    const int hashSize = 64;
    byte[] seed;
    BigInteger curGen;
    byte[] derivedValues;

    long curSize;
    long curIndex;

    public uint NextNonSeededUInt()
    {
        Span<byte> num = stackalloc byte[sizeof(uint)];
        RandomNumberGenerator.Fill(num);
        return BinaryPrimitives.ReadUInt32LittleEndian(num);
    }
    public int NextNonSeededInt(int min, int max)
    {
        uint numRes = NextNonSeededUInt();

        int modMin = max + 1 - min;
        if (modMin == 0) modMin = 1;
        return (int)(min + numRes % modMin);
    }

    public void Setup(byte[] seed)
    {
        this.seed = seed;
        DeriveValues(10);
    }

    void DeriveValues(int tableSize = 10)
    {
        curSize = tableSize * hashSize;
        curIndex = 0;
        curGen++;

        var nseed = new BigInteger(seed) * curGen;
        //var nseed = nseedNum.ToByteArray();

        derivedValues = new byte[hashSize * tableSize];
        Span<byte> dval = derivedValues;
        for(int i = 0; i < tableSize; i++)
        {
            nseed += 1;
            SHA512.HashData(nseed.ToByteArray(), dval[(i * hashSize)..]);
        }
    }

    public byte NextByte()
    {
        if (curIndex >= curSize)
            DeriveValues(10);
        return derivedValues[curIndex++];
    }

    public void FillBytes(Span<byte> bytes)
    {
        int size = bytes.Length;
        //long final = (curSize - curIndex) - size;
        for (long i = 0; i < size; i++)
        {
            if (curIndex >= curSize)
                DeriveValues(10);
            bytes[(int)i] = derivedValues[curIndex++];
        }
    }

    public int NextInt(int min, int max)
    {
        byte[] num = new byte[sizeof(int)];
        FillBytes(num);
        uint numRes = BinaryPrimitives.ReadUInt32LittleEndian(num);
        /*if (numRes > max)
            numRes %= max;
        else if(numRes < min)
        {
            if (min < 0)
                numRes %= min;
            else if (min > 0)
                numRes = -(numRes % min);
            else
                numRes = -numRes % max;
        }*/
        int modMin = max + 1 - min;
        if (modMin == 0) modMin = 1;
        return (int)(min + numRes % modMin);
    }

    public BigInteger Next(BigInteger min, BigInteger max)
    {
        //return Next(min.GetByteCount(), max.GetByteCount());
        int minSize = min.GetByteCount();
        var numRes = Next(sizeof(decimal) + minSize, sizeof(decimal) * (max.GetByteCount() * minSize));

        numRes = min + numRes % (max + 1 - min);

        if (min >= 0 && numRes < 0)
            numRes = -numRes;

        return numRes;
    }
    public BigInteger Next(int minSize, int maxSize)
    {
        byte[] num = new byte[NextInt(minSize, maxSize)];
        FillBytes(num);
        return new BigInteger(num);
    }
    public BigInteger Next(int fixedSize = 32)
    {
        byte[] num = new byte[fixedSize];
        FillBytes(num);
        return new BigInteger(num);
    }
    public BigInteger NextUnsigned(int fixedSize = 32)
    {
        byte[] num = new byte[fixedSize];
        FillBytes(num);
        return new BigInteger(num, true);
    }
}
