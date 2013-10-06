/* Converted to D from output/base64.h by htod */
module nettle.base64;
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
struct base64_encode_ctx
{
    uint word;
    uint bits;
}
void  nettle_base64_encode_init(base64_encode_ctx *ctx);
uint  nettle_base64_encode_single(base64_encode_ctx *ctx, uint8_t *dst, uint8_t src);
uint  nettle_base64_encode_update(base64_encode_ctx *ctx, uint8_t *dst, uint length, uint8_t *src);
uint  nettle_base64_encode_final(base64_encode_ctx *ctx, uint8_t *dst);
void  nettle_base64_encode_raw(uint8_t *dst, uint length, uint8_t *src);
void  nettle_base64_encode_group(uint8_t *dst, uint32_t group);
struct base64_decode_ctx
{
    uint word;
    uint bits;
    uint padding;
}
void  nettle_base64_decode_init(base64_decode_ctx *ctx);
int  nettle_base64_decode_single(base64_decode_ctx *ctx, uint8_t *dst, uint8_t src);
int  nettle_base64_decode_update(base64_decode_ctx *ctx, uint *dst_length, uint8_t *dst, uint src_length, uint8_t *src);
int  nettle_base64_decode_final(base64_decode_ctx *ctx);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const _STDINT_HAVE_INT_FAST32_T = 1;
const __NETTLE_STDINT_H = 1;
const _GENERATED_STDINT_H = " ";
const _STDINT_HAVE_STDINT_H = 1;
const BASE64_BINARY_BLOCK_SIZE = 3;
const BASE64_TEXT_BLOCK_SIZE = 4;
const BASE64_ENCODE_FINAL_LENGTH = 3;
