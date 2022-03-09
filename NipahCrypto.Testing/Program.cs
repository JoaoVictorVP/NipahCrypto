using NipahCrypto.Core;
using NipahCrypto.SecretGrid;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

Console.WriteLine("Welcome to the Nipah Crypto Testing Facility!");

Console.WriteLine("SecretGrid Algorithm Test");

var sgrid = new SGrid();
sgrid.Initialize();

// Console.WriteLine($"Public Key (Size: {sgrid.PublicKey.GetByteCount()}): " + sgrid.PublicKey + '\n');
Console.WriteLine($"Public Key (Size: {sgrid.PublicKey.GetByteCount()})" + '\n');
// Console.WriteLine($"Master Private Key (Size: {sgrid.MasterPrivateKey.GetByteCount()}): " + sgrid.MasterPrivateKey + '\n');
Console.WriteLine($"Master Private Key (Size: {sgrid.MasterPrivateKey.GetByteCount()})" + '\n');
Console.WriteLine($"Common Signature Key (Size: {sgrid.PrivateKeys[0].XYZ.GetByteCount()})" + '\n');

Console.WriteLine("Average Signature Key Size: " + sgrid.PrivateKeys.Average(p => (decimal)p.XYZ.GetByteCount()));

Console.WriteLine("Minimum Signature Key Size: " + sgrid.PrivateKeys.Select(p => p.XYZ.GetByteCount()).Min());
Console.WriteLine("Maximum Signature Key Size: " + sgrid.PrivateKeys.Select(p => p.XYZ.GetByteCount()).Max());

Console.Write("\nMessage to be signed:\n> ");
string message = Console.ReadLine();
byte[] plaintext = Encoding.Unicode.GetBytes(message);

Console.WriteLine();

var rng = new NPRNG();
rng.Setup(RandomNumberGenerator.GetBytes(32));
var random = new Random();

//byte[] draw = new byte[107000];

//rng.FillBytes(draw);

/*const int iterations = 100_000;
BigInteger min = 0, max = 10;

List<BigInteger> draw = new (iterations);
for (int i = 0; i < 107000; i++)
    //draw.Add(random.Next(min, max));
    draw.Add(rng.Next(min, max));

//var sorted = draw.OrderBy(b => b.ToString());
var sorted = draw;

StringBuilder sb = new StringBuilder(iterations * 4);

int do_max = iterations;
foreach(var b in sorted)
{
    //Console.Write(b.ToString() + ',');

    sb.AppendLine(b.ToString());

    do_max--;
    if (do_max <= 0)
        break;
}

File.WriteAllText("Random.txt", sb.ToString());

Console.WriteLine("Ready!");*/

//Console.ReadKey(true);

long gens = 0;
while (true)
{
    gens++;

    var signature = sgrid.Sign(plaintext);

    //Console.WriteLine($"True Signature (Size: {signature.Length}): " + Convert.ToHexString(signature) + '\n');
    Console.WriteLine($"True Signature (Size: {signature.Length})" + '\n');

    var fsignature = sgrid.FalsifySignatureWithOtherAsExample(sgrid.PublicKey, plaintext, signature);

    //Console.WriteLine($"False Signature (Size: {fsignature.Length}): " + Convert.ToHexString(fsignature));
    Console.WriteLine($"False Signature (Size: {fsignature.Length})");

    Console.WriteLine();

    var verify = sgrid.Verify(sgrid.PublicKey, plaintext, signature);

    Console.WriteLine("<True> Verify Signature Results: " + verify + '\n');

    verify = sgrid.Verify(sgrid.PublicKey, plaintext, fsignature);

    Console.WriteLine("<False> Verify Signature Results: " + verify);

    /*if (verify)
    {
        Console.WriteLine("Generations: " + gens + '\n');

        Console.WriteLine($"True Signature (Size: {signature.Length}): " + Convert.ToHexString(signature) + '\n');

        Console.WriteLine($"False Signature (Size: {fsignature.Length}): " + Convert.ToHexString(fsignature));

        Console.ReadKey(true);
    }*/
    Console.ReadKey(true);
}