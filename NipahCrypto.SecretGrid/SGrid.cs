using NipahCrypto.Core;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NipahCrypto.SecretGrid;

public partial class SGrid
{
    const int minKeys = 1024, maxKeys = 1024;
    const int keySize = 32;
    static bint prime = 999999000001, primeX3 = prime * prime * prime;
    //static bint prime = 3, primeX3 = prime * 2;
    public bint PublicKey;
    public Point[] PrivateKeys;
    public bint MasterPrivateKey;

    NPRNG rng;

    public byte[] Sign(Span<byte> data)
    {
        var pkey = PickPrivateKey();

        bint maskX = rng.Next(prime, primeX3),
            //maskY = rng.Next(prime, primeX3),
            maskZ = rng.Next(prime, primeX3);

        if (maskX == 0) maskX = 3;
        if (maskZ == 0) maskZ = 3;
        //bint mask = maskX * maskY * maskZ;
        // Sends only XZ, the rest Y will be sent as proof for data
        bint factor = maskX * maskZ;

        bint tamperProof = PrivateKeys.Where(p => p != pkey).Aggregate((a, b) => new Point(a.X * b.X, a.Y * b.Y, a.Z * b.Z)).XYZ;

        // Compresses all data to around 128-bit (16-bytes) data
        bint ndata = digest_data(data); // new bint(SHA512.HashData(data));

        return do_sign(in pkey, in ndata, in maskX, in maskZ, in factor, in tamperProof);
    }
    bint digest_data(Span<byte> data)
    {
        Span<byte> hash = stackalloc byte[64];

        SHA512.HashData(data, hash);
        SHA256.HashData(hash, hash);
        //SHA1.HashData(hash[..32], hash);

        return new bint(hash[..32]);
    }
    byte[] do_sign(in Point pkey, in bint ndata, in bint maskX, in bint maskZ, in bint factor, in bint tamperProof)
    {
        bint sign = (pkey.X * maskX) * (pkey.Z * maskZ) * ndata;

        return finalize_sign(pkey.Y, in factor, in tamperProof, in sign);
    }
    byte[] finalize_sign(in bint yAxis, in bint factor, in bint tamperProof, in bint sign)
    {
        var result = new List<byte>(keySize);

        byte[] sint = new byte[sizeof(int)];

        // Signature
        BinaryPrimitives.WriteInt32LittleEndian(sint, sign.GetByteCount());
        result.AddRange(sint);
        result.AddRange(sign.ToByteArray());

        // Factor (Mask)
        BinaryPrimitives.WriteInt32LittleEndian(sint, factor.GetByteCount());
        result.AddRange(sint);
        result.AddRange(factor.ToByteArray());

        // Missing Y Part Size
        BinaryPrimitives.WriteInt32LittleEndian(sint, yAxis.GetByteCount());
        result.AddRange(sint);

        // Tamper Proof
        //BinaryPrimitives.WriteInt32LittleEndian(sint, tamperProof.GetByteCount());
        //result.AddRange(sint);
        result.AddRange(tamperProof.ToByteArray());

        // Missing Y Part
        result.AddRange(yAxis.ToByteArray());

        /*Debug.WriteLine("PublicKey " + PublicKey);
        Debug.WriteLine("TamperProof " + tamperProof);
        Debug.WriteLine("Sign " + sign);
        Debug.WriteLine("Factor " + factor);
        Debug.WriteLine("NData " + ndata);
        Debug.WriteLine("MissingY " + pkey.Y);*/

        return result.ToArray();
    }

    public byte[] FalsifySignature(Span<byte> data)
    {
        //var pkey = PickPrivateKey();
        var pkey = new Point(rng.Next(keySize), rng.Next(keySize), rng.Next(keySize));

        bint maskX = rng.Next(prime, primeX3),
            //maskY = rng.Next(prime, primeX3),
            maskZ = rng.Next(prime, primeX3);

        if (maskX == 0) maskX = 3;
        if (maskZ == 0) maskZ = 3;
        //bint mask = maskX * maskY * maskZ;
        // Sends only XZ, the rest Y will be sent as proof for data
        bint factor = maskX * maskZ;

        bint tamperProof = PrivateKeys.Where(p => p != pkey).Aggregate((a, b) => new Point(a.X * b.X, a.Y * b.Y, a.Z * b.Z)).XYZ;

        bint ndata = digest_data(data); // new bint(SHA512.HashData(data));

        return do_sign(in pkey, in ndata, in maskX, in maskZ, in factor, in tamperProof);
    }

    public byte[] FalsifySignatureWithOtherAsExample(bint publicKey, Span<byte> data, Span<byte> signature)
    {
        //var pkey = PickPrivateKey();
        extract_signature_data(signature, out bint missingY, out bint sign, out bint factor, out bint tamperProof);

        bint ndata = digest_data(data); // new bint(SHA512.HashData(data));

        bint xyAbs = sign / ndata;

        byte[] fakeData = Encoding.Unicode.GetBytes("Another completely random message");
        bint fndata = digest_data(fakeData);

        bint fsign = xyAbs * fndata;

        return finalize_sign(in missingY, in factor, in tamperProof, in fsign);
    }

    public bool Verify(bint publicKey, Span<byte> data, Span<byte> signature)
    {
        extract_signature_data(signature, out bint missingY, out bint sign, out bint factor, out bint tamperProof);

        bint ndata = digest_data(data); // new bint(SHA512.HashData(data));

        return (publicKey / tamperProof) == (((sign / factor) / ndata) * missingY);
    }
    void extract_signature_data(Span<byte> signature, out bint missingY, out bint sign, out bint factor, out bint tamperProof)
    {
        // Extract: Signature
        int signSize = BinaryPrimitives.ReadInt32LittleEndian(signature[..sizeof(int)]);
        Span<byte> _sign = signature.Slice(sizeof(int), signSize);

        // Extract: Factor (Mask)
        int factorSize = BinaryPrimitives.ReadInt32LittleEndian(signature.Slice(sizeof(int) + signSize, sizeof(int)));
        Span<byte> _factor = signature.Slice((sizeof(int) * 2) + signSize, factorSize);

        // Extract: Tamper Proof
        int missingYSize = BinaryPrimitives.ReadInt32LittleEndian(signature.Slice((sizeof(int) * 2) + signSize + factorSize, sizeof(int)));
        Span<byte> _tamperProof = signature[((sizeof(int) * 3) + signSize + factorSize)..^missingYSize];

        Span<byte> _missingY = signature[((sizeof(int) * 3) + signSize + factorSize + _tamperProof.Length)..];
        missingY = new bint(_missingY);

        sign = new bint(_sign);
        factor = new bint(_factor);
        tamperProof = new bint(_tamperProof);
    }

    Point PickPrivateKey()
    {
        int pkeyCount = PrivateKeys.Length;
        //int pkey = rng.NextInt(0, pkeyCount);
        // Should be non-seeded for trully randomness when signing
        int pkey = rng.NextNonSeededInt(0, pkeyCount);
        if (pkey >= pkeyCount) pkey %= pkeyCount;

        return PrivateKeys[pkey];
    }

    public void Initialize()
    {
        MasterPrivateKey = new bint(RandomNumberGenerator.GetBytes(keySize));
        rng.Setup(MasterPrivateKey.ToByteArray());

        int keyCount = rng.NextInt(minKeys, maxKeys);
        PrivateKeys = new Point[keyCount];
        for(int i = 0; i < keyCount; i++)
        {
            //regen:
            var keyX = rng.Next(keySize);
            var keyY = rng.Next(keySize);
            var keyZ = rng.Next(keySize);

            //var key = new Point(keyX, keyY, keyZ);

            //if (key.XYZ.GetByteCount() != (keySize * 3))
            //    goto regen;

            //PrivateKeys[i] = key;

            PrivateKeys[i] = new Point(keyX, keyY, keyZ);
        }

        PublicKey = PrivateKeys.Aggregate((a, b) => new Point(a.X * b.X, a.Y * b.Y, a.Z * b.Z)).XYZ;
        //PublicKey = new Point(rng.Next(keySize), rng.Next(keySize), rng.Next(keySize));
    }
}
public record struct Point(bint X, bint Y, bint Z)
{
    public bint XYZ => X * Y * Z;

    public bint XY => X * Y;
    public bint XZ => X * Z;
    public bint YZ => Y * Z;
}
