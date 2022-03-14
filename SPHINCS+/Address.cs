using NipahCrypto.Core;

namespace SPHINCSPlus;

public unsafe static class Address
{
    /// <summary>
    /// DOC: Specify wich level of Merkle tree (the "layer") we're working on
    /// </summary>
    /// <param name="addr"></param>
    /// <param name="layer"></param>
    public static void SetLayerAddress(address addr, uint layer)
    {
        addr.values[SPX_OFFSET_LAYER] = layer;
    }
    /// <summary>
    /// DOC: Specify which Merkle tree within the level (the "tree address") we're working on
    /// </summary>
    /// <param name="addr"></param>
    /// <param name="tree"></param>
    public static void SetTreeAddress(address addr, ulong tree)
    {
        if ((SPX_OFFSET_TREE_HGT * (SPX_D - 1)) > 64)
            throw new Exception("Subtree addressing is currently limited to at most 2^64 trees");
        Utils.UllToBytes(&(addr.values[SPX_OFFSET_TREE]), 8, tree);
    }
    public static void SetType(address addr, uint type)
    {
        addr.values[SPX_OFFSET_TYPE] = type;
    }
    public static void CopySubtreeAddress(address @out, address @in)
    {
        memcpy(@out.values, @in.values, SPX_OFFSET_TREE + 8);
    }
    public static void SetKeypairAdress(address addr, uint keypair)
    {
        if (SPX_FULL_HEIGHT / SPX_D > 8)
            addr.values[SPX_OFFSET_KP_ADDR2] = keypair >> 8;

        addr.values[SPX_OFFSET_KP_ADDR1] = keypair;
    }
    public static void CopyKeypairAddress(address @out, address @in)
    {
        memcpy(@out.values, @in.values, SPX_OFFSET_TREE + 8);
        if (SPX_FULL_HEIGHT / SPX_D > 8)
            @out.values[SPX_OFFSET_KP_ADDR2] = @in.values[SPX_OFFSET_KP_ADDR2];
        @out.values[SPX_OFFSET_KP_ADDR1] = @in.values[SPX_OFFSET_KP_ADDR1];
    }
    public static void SetChainAddress(address addr, uint chain)
    {
        ((uint*)(&((byte*)addr.values)[SPX_OFFSET_TREE_HGT]))[SPX_OFFSET_CHAIN_ADDR] = chain;
    }
    public static void SetHashAddress(address addr, uint hash)
    {
        ((uint*)(&((byte*)addr.values)[SPX_OFFSET_TREE_HGT]))[SPX_OFFSET_HASH_ADDR] = hash;
    }
    public static void SetTreeHeight(address addr, uint treeHeight)
    {
        //byte* oaddr = ((byte*)addr.values);
        //uint* faddr = ((uint*)(&((byte*)addr.values)[SPX_OFFSET_TREE_HGT]));
        ((uint*)(&((byte*)addr.values)[SPX_OFFSET_TREE_HGT]))[SPX_OFFSET_TREE_HGT] = treeHeight;

        // Original
        //addr.values[SPX_OFFSET_TREE_HGT] = treeHeight;
    }
    public static void SetTreeIndex(address addr, uint treeIndex)
    {
        Utils.U32ToBytes(&((byte*)addr.values)[SPX_OFFSET_TREE_INDEX], treeIndex);
       // Utils.U32ToBytes(((byte*)addr.values)[SPX_OFFSET_TREE_INDEX], treeIndex);
    }
 }
