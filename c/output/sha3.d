/* Converted to D from output/sha3.h by htod */
module nettle.sha3;
struct _N1
{
}
extern (C):
alias _N1 __mpz_struct;
alias __mpz_struct [1]mpz_t;
alias ubyte uint8_t;
alias uint uint32_t;
alias ulong uint64_t;
alias void function(void *ctx, uint length, uint8_t *dst)nettle_random_func;
alias void function(void *ctx, int c)nettle_progress_func;
alias void *function(void *ctx, void *p, uint length)nettle_realloc_func;
alias void function(void *ctx, uint length, uint8_t *key)nettle_set_key_func;
alias void function(void *ctx, uint length, uint8_t *dst, uint8_t *src)nettle_crypt_func;
alias void function(void *ctx)nettle_hash_init_func;
alias void function(void *ctx, uint length, uint8_t *src)nettle_hash_update_func;
alias void function(void *ctx, uint length, uint8_t *dst)nettle_hash_digest_func;
alias uint function(uint length)nettle_armor_length_func;
alias void function(void *ctx)nettle_armor_init_func;
alias uint function(void *ctx, uint8_t *dst, uint src_length, uint8_t *src)nettle_armor_encode_update_func;
alias uint function(void *ctx, uint8_t *dst)nettle_armor_encode_final_func;
alias int function(void *ctx, uint *dst_length, uint8_t *dst, uint src_length, uint8_t *src)nettle_armor_decode_update_func;
alias int function(void *ctx)nettle_armor_decode_final_func;
struct sha3_state
{
    uint64_t [25]a;
}
void  nettle_sha3_permute(sha3_state *state);
uint  _nettle_sha3_update(sha3_state *state, uint block_size, uint8_t *block, uint pos, uint length, uint8_t *data);
void  _nettle_sha3_pad(sha3_state *state, uint block_size, uint8_t *block, uint pos);
struct sha3_224_ctx
{
    sha3_state state;
    uint index;
    uint8_t [144]block;
}
void  nettle_sha3_224_init(sha3_224_ctx *ctx);
void  nettle_sha3_224_update(sha3_224_ctx *ctx, uint length, uint8_t *data);
void  nettle_sha3_224_digest(sha3_224_ctx *ctx, uint length, uint8_t *digest);
struct sha3_256_ctx
{
    sha3_state state;
    uint index;
    uint8_t [136]block;
}
void  nettle_sha3_256_init(sha3_256_ctx *ctx);
void  nettle_sha3_256_update(sha3_256_ctx *ctx, uint length, uint8_t *data);
void  nettle_sha3_256_digest(sha3_256_ctx *ctx, uint length, uint8_t *digest);
struct sha3_384_ctx
{
    sha3_state state;
    uint index;
    uint8_t [104]block;
}
void  nettle_sha3_384_init(sha3_384_ctx *ctx);
void  nettle_sha3_384_update(sha3_384_ctx *ctx, uint length, uint8_t *data);
void  nettle_sha3_384_digest(sha3_384_ctx *ctx, uint length, uint8_t *digest);
struct sha3_512_ctx
{
    sha3_state state;
    uint index;
    uint8_t [72]block;
}
void  nettle_sha3_512_init(sha3_512_ctx *ctx);
void  nettle_sha3_512_update(sha3_512_ctx *ctx, uint length, uint8_t *data);
void  nettle_sha3_512_digest(sha3_512_ctx *ctx, uint length, uint8_t *digest);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const SHA3_STATE_LENGTH = 25;
const SHA3_224_DIGEST_SIZE = 28;
const SHA3_224_DATA_SIZE = 144;
const SHA3_256_DIGEST_SIZE = 32;
const SHA3_256_DATA_SIZE = 136;
const SHA3_384_DIGEST_SIZE = 48;
const SHA3_384_DATA_SIZE = 104;
const SHA3_512_DIGEST_SIZE = 64;
const SHA3_512_DATA_SIZE = 72;
void main(){}
