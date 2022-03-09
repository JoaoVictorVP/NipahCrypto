namespace SPHINCSPlus;

public unsafe struct SpxCtx
{
    public fixed byte PublicSeed[SPX_N];
    public fixed byte SecretKeySeed[SPX_N];

    // Yes it is currently SHA256
    public fixed byte StateSeeded[40];
}
