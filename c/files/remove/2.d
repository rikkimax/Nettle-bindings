struct sha256_ctx
{
    uint32_t [8]state;
    uint32_t count_low;
    uint32_t count_high;
    uint8_t [64]block;
    uint index;
}