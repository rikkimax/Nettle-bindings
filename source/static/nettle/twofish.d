/* Converted to D from output/twofish.h by htod */
module nettle.twofish;
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
struct twofish_ctx
{
    uint32_t [40]keys;
    uint32_t [256][4]s_box;
}
void  nettle_twofish_set_key(twofish_ctx *ctx, uint length, uint8_t *key);
void  nettle_twofish_encrypt(twofish_ctx *ctx, uint length, uint8_t *dst, uint8_t *src);
void  nettle_twofish_decrypt(twofish_ctx *ctx, uint length, uint8_t *dst, uint8_t *src);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const _STDINT_HAVE_INT_FAST32_T = 1;
const __NETTLE_STDINT_H = 1;
const _GENERATED_STDINT_H = " ";
const _STDINT_HAVE_STDINT_H = 1;
const TWOFISH_BLOCK_SIZE = 16;
const TWOFISH_MIN_KEY_SIZE = 16;
const TWOFISH_MAX_KEY_SIZE = 32;
const TWOFISH_KEY_SIZE = 32;
