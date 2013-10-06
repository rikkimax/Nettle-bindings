/* Converted to D from output/base16.h by htod */
module nettle.base16;
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
void  nettle_base16_encode_single(uint8_t *dst, uint8_t src);
void  nettle_base16_encode_update(uint8_t *dst, uint length, uint8_t *src);
struct base16_decode_ctx
{
    uint word;
    uint bits;
}
void  nettle_base16_decode_init(base16_decode_ctx *ctx);
int  nettle_base16_decode_single(base16_decode_ctx *ctx, uint8_t *dst, uint8_t src);
int  nettle_base16_decode_update(base16_decode_ctx *ctx, uint *dst_length, uint8_t *dst, uint src_length, uint8_t *src);
int  nettle_base16_decode_final(base16_decode_ctx *ctx);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const _STDINT_HAVE_INT_FAST32_T = 1;
const __NETTLE_STDINT_H = 1;
const _GENERATED_STDINT_H = " ";
const _STDINT_HAVE_STDINT_H = 1;
