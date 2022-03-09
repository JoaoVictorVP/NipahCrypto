global using static SPHINCSPlus.CONSTANTS;
global using static SPHINCSPlus.NATIVE;
namespace SPHINCSPlus;

public static class CONSTANTS
{
    /// <summary>
    /// The hash size in bytes (apparently)
    /// </summary>
    public const int SPX_N = 32;
}

public unsafe static class NATIVE
{
    public static void memcpy(void* to, void* from, ulong size)
    {
        byte* bto = (byte*)to;
        byte* bfrom = (byte*)from;

        for (ulong i = 0; i < size; i++)
            bto[i] = bfrom[i];
    }
}