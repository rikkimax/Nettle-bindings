struct sha512_ctx
{
    uint64_t [8]state;
    uint64_t count_low;
    uint64_t count_high;
    uint8_t [128]block;
    uint index;
}