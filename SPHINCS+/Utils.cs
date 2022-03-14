namespace SPHINCSPlus;

public static unsafe class Utils
{
    public static void UllToBytes(void* @out, uint outlen, ulong @in)
    {
        ulong* nout = (ulong*)@out;
        for(uint i = outlen - 1; i >= 0; i--)
        {
            nout[i] = @in & 0xff;
            @in = @in >> 8;
        }
    }
    public static void U32ToBytes(byte* @out, uint @in)
    {
        @out[0] = (byte)(@in >> 24);
        @out[1] = (byte)(@in >> 16);
        @out[2] = (byte)(@in >> 8);
        @out[3] = (byte)@in;
    }
    public static ulong BytesToUll(in byte* @in, uint inlen)
    {
        ulong retVal = 0;
        for(uint i = 0; i < inlen; i++)
        {
           // ulong _in = @in[i];

            retVal |= (ulong)(@in[i]) << (int)((8 * (inlen - 1)) - 1);

        }
        return retVal;
    }

    public static void ComputeRoot(byte* root, in byte* leaf, uint leafIdx, uint idxOffset, in byte* authPath, uint treeHeight, in SpxCtx* ctx, address addr)
    {
        byte* buffer = stackalloc byte[2 * SPX_N];

        if((leafIdx & 1) == 1)
        {
            memcpy(buffer + SPX_N, leaf, SPX_N);
            memcpy(buffer, authPath, SPX_N);
        }
        else
        {
            memcpy(buffer, leaf, SPX_N);
            memcpy(buffer + SPX_N, authPath, SPX_N);
        }
        // Strange, this should be authPath += SPX_N according to C code, but okay I presume it is different between C and C# how plus works with constant pointer variables (maybe the C compiler knows he's trying to change the value because it is constant, whereas C# compiler does not) WATCH
        *authPath += SPX_N;

        for(uint i = 0; i < treeHeight - 1; i++)
        {
            leafIdx >>= 1;
            idxOffset >>= 1;

            // DOC: Set the address of the node we're creating.
            Address.SetTreeHeight(addr, treeHeight);
            Address.SetTreeIndex(addr, leafIdx + idxOffset);

            // DOC: Pick the right or left neighbor, depending on parity of the node.
            if ((leafIdx & 1) == 1)
            {
                //THash(buffer + SPX_N, buffer, 2, ctx, addr);
                memcpy(buffer, authPath, SPX_N);
            }
            else
            {
                //THash(buffer, buffer, 2, ctx, addr);
                memcpy(buffer + SPX_N, authPath, SPX_N);
            }
            // WATCH
            *authPath += SPX_N;
        }

        // DOC: The last iteration is exceptional; we do not copy an auth_path @authPath node.
        leafIdx >>= 1;
        idxOffset >>= 1;
        Address.SetTreeHeight(addr, treeHeight);
        Address.SetTreeIndex(addr, leafIdx + idxOffset);
        //THash(root, buffer, 2, ctx, addr);
    }

    public delegate void tree_hash_fun(byte* leaf, in SpxCtx* ctx, uint addrIdx, in address treeAddr);
    public static void TreeHash(byte* root, byte* authPath, in SpxCtx* ctx, uint leafIdx, uint idxOffset, uint treeHeight, tree_hash_fun genLeaf, address treeAddr)
    {
        byte* stack = stackalloc byte[(int)(treeHeight + 1) * SPX_N];
        uint* heights = stackalloc uint[(int)treeHeight + 1];
        uint offset = 0;
        uint idx;
        uint treeIdx;

        // Changed uint << to int WATCH
        for(idx = 0; idx < (uint)(1 << (int)treeHeight); idx++)
        {
            genLeaf(stack + offset * SPX_N, ctx, idx + idxOffset, treeAddr);
            offset++;
            heights[offset - 1] = 0;

            // DOC: If this is a node we need for the auth path...
            if((leafIdx ^ 0x1) == idx)
            {
                memcpy(authPath, stack + (offset - 1) * SPX_N, SPX_N);
            }

            // DOC: While the top-most nodes are of equal height...
            while(offset >= 2 && heights[offset - 1] == heights[offset - 2])
            {
                // DOC: Compute index of the new node, in the next layer (change from uint >> uint, to uint >> int) WATCH
                treeIdx = (idx >> (int)(heights[offset - 1] + 1));

                // DOC: Set the address of the node we're creating.
                Address.SetTreeHeight(treeAddr, heights[offset - 1] + 1);
                // From uint >> uint to uint >> int WATCH
                Address.SetTreeIndex(treeAddr, treeIdx + (idxOffset >> (int)(heights[offset - 1] + 1)));

                // DOC: Hash the top-most nodes from the stack together. WATCH
                //THash(stack + (offset - 2) * SPX_N, stack + (offset - 2) * SPX_N, 2, ctx, treeAddr);
                offset--;

                // DOC: Note that the top-most node is now one layer higher.
                heights[offset - 1]++;

                // DOC: If this is a node we need for the auth path... WATCH
                if(((leafIdx >> (int)heights[offset - 1]) ^ 0x1) == treeIdx)
                {
                    memcpy(authPath + heights[offset - 1] * SPX_N, stack + (offset - 1) * SPX_N, SPX_N);
                }
            }
        }
        memcpy(root, stack, SPX_N);
    }
}
