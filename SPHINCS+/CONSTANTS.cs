//#define W256
#define W16

global using static SPHINCSPlus.CONSTANTS;
global using static SPHINCSPlus.NATIVE;
using System.Threading.Channels;
using System;

namespace SPHINCSPlus;

public static class CONSTANTS
{
    /// <summary>
    /// The hash size in bytes (apparently)
    /// </summary>
    public const int SPX_N = 32;
    /// <summary>
    /// Height of hypertrees
    /// </summary>
    public const int SPX_FULL_HEIGHT = 68;
    /// <summary>
    /// Number of subtree layer
    /// </summary>
    public const int SPX_D = 17;
    /// <summary>
    /// FORS tree dimensions (height)
    /// </summary>
    public const int SPX_FORS_HEIGHT = 9;
    /// <summary>
    /// FORS tree dimensions (trees)
    /// </summary>
    public const int SPX_FORS_TREES = 35;
    /// <summary>
    /// Winternitz parameter
    /// </summary>
    public const int SPX_WOTS_W = 16;

    public const int SPX_ADDR_BYTES = 32;

    /// <summary>
    /// WOTS parameters
    /// </summary>
    public const int SPX_WOTS_LOGW =
#if W256
        8;
#elif W16
        4;
#endif

    public const int SPX_WOTS_LEN1 = (8 * SPX_N / SPX_WOTS_LOGW);

    public const int SPX_WOTS_LEN2 = 3;

    public const int SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2);

    public const int SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N);
    public const int SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES;

    /// <summary>
    /// Subtree size
    /// </summary>
    public const int SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);

    /// <summary>
    /// FORS parameters (msg-bytes)
    /// </summary>
    public const int SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8);
    /// <summary>
    /// FORS parameters (bytes)
    /// </summary>
    public const int SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N);
    /// <summary>
    /// FORS parameters (pk bytes)
    /// </summary>
    public const int SPX_FORS_PK_BYTES = SPX_N;

    /// <summary>
    /// Resulting SPX sizes (bytes)
    /// </summary>
    public const int SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
    /// <summary>
    /// Resulting SPX sizes (pk-bytes)
    /// </summary>
    public const int SPX_PK_BYTES = (2 * SPX_N);
    /// <summary>
    /// Resulting SPX sizes (secret key bytes)
    /// </summary>
    public const int SPK_SK_BYTES = (2 * SPX_N + SPX_PK_BYTES);

/// <summary>
/// Optionally, signing can be made non-deterministic using optrand.<br/>
/// This can help counter side-channel attacks that would benefit from getting a large number of traces when the signer uses the same nodes.
    /// </summary>
    public const int SPX_OPTRAND_BYTES = 32;

    #region Offsets

    public const int SPX_OFFSET_LAYER = 0;   /* The byte used to specify the Merkle tree layer */
    public const int SPX_OFFSET_TREE = 1;   /* The start of the 8 byte field used to specify the tree */
    public const int SPX_OFFSET_TYPE = 9;   /* The byte used to specify the hash type (reason) */
    public const int SPX_OFFSET_KP_ADDR2 = 12;  /* The high byte used to specify the key pair (which one-time signature) */
    public const int SPX_OFFSET_KP_ADDR1 = 13;  /* The low byte used to specify the key pair */
    public const int SPX_OFFSET_CHAIN_ADDR = 17;  /* The byte used to specify the chain address (which Winternitz chain) */
    public const int SPX_OFFSET_HASH_ADDR = 21;  /* The byte used to specify the hash address (where in the Winternitz chain) */
    public const int SPX_OFFSET_TREE_HGT = 17;  /* The byte used to specify the height of this node in the FORS or Merkle tree */
    public const int SPX_OFFSET_TREE_INDEX = 18; /* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */

    public const int SPX_SHA256 = 1;

    #endregion
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

    public static T* OpInBytesOffset<T>(T* ptr, int offset) where T : unmanaged
    {
        return ((T*)(&((byte*)ptr)[SPX_OFFSET_TREE_HGT]));
        //((uint*)(&((byte*)addr.values)[SPX_OFFSET_TREE_HGT]))
    }
}