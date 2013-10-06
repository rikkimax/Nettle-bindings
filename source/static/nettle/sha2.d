/* Converted to D from output/sha2.h by htod */
module nettle.sha2;
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
struct sha256_ctx
{
    uint32_t [8]state;
    uint32_t count_low;
    uint32_t count_high;
    uint8_t [64]block;
    uint index;
}
void  nettle_sha256_init(sha256_ctx *ctx);
void  nettle_sha256_update(sha256_ctx *ctx, uint length, uint8_t *data);
void  nettle_sha256_digest(sha256_ctx *ctx, uint length, uint8_t *digest);
void  _nettle_sha256_compress(uint32_t *state, uint8_t *data, uint32_t *k);
void  nettle_sha224_init(sha256_ctx *ctx);
void  nettle_sha224_digest(sha256_ctx *ctx, uint length, uint8_t *digest);
struct sha512_ctx
{
    uint64_t [8]state;
    uint64_t count_low;
    uint64_t count_high;
    uint8_t [128]block;
    uint index;
}
void  nettle_sha512_init(sha512_ctx *ctx);
void  nettle_sha512_update(sha512_ctx *ctx, uint length, uint8_t *data);
void  nettle_sha512_digest(sha512_ctx *ctx, uint length, uint8_t *digest);
void  _nettle_sha512_compress(uint64_t *state, uint8_t *data, uint64_t *k);
void  nettle_sha384_init(sha512_ctx *ctx);
void  nettle_sha384_digest(sha512_ctx *ctx, uint length, uint8_t *digest);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const _STDINT_HAVE_INT_FAST32_T = 1;
const __NETTLE_STDINT_H = 1;
const _GENERATED_STDINT_H = " ";
const _STDINT_HAVE_STDINT_H = 1;
const SHA256_DIGEST_SIZE = 32;
const SHA256_DATA_SIZE = 64;
const _SHA256_DIGEST_LENGTH = 8;
const SHA224_DIGEST_SIZE = 28;
const SHA512_DIGEST_SIZE = 64;
const SHA512_DATA_SIZE = 128;
const _SHA512_DIGEST_LENGTH = 8;
const SHA384_DIGEST_SIZE = 48;
