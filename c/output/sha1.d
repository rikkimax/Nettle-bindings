/* Converted to D from output/sha1.h by htod */
module nettle.sha1;
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
struct sha1_ctx
{
    uint32_t [5]state;
    uint32_t count_low;
    uint32_t count_high;
    uint8_t [64]block;
    uint index;
}
void  nettle_sha1_init(sha1_ctx *ctx);
void  nettle_sha1_update(sha1_ctx *ctx, uint length, uint8_t *data);
void  nettle_sha1_digest(sha1_ctx *ctx, uint length, uint8_t *digest);
void  _nettle_sha1_compress(uint32_t *state, uint8_t *data);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const _STDINT_HAVE_INT_FAST32_T = 1;
const __NETTLE_STDINT_H = 1;
const _GENERATED_STDINT_H = " ";
const _STDINT_HAVE_STDINT_H = 1;
const SHA1_DIGEST_SIZE = 20;
const SHA1_DATA_SIZE = 64;
const _SHA1_DIGEST_LENGTH = 5;
void main(){}
