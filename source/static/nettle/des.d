/* Converted to D from output/des.h by htod */
module nettle.des;
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
struct des_ctx
{
    uint32_t [32]key;
}
int  nettle_des_set_key(des_ctx *ctx, uint8_t *key);
void  nettle_des_encrypt(des_ctx *ctx, uint length, uint8_t *dst, uint8_t *src);
void  nettle_des_decrypt(des_ctx *ctx, uint length, uint8_t *dst, uint8_t *src);
int  nettle_des_check_parity(uint length, uint8_t *key);
void  nettle_des_fix_parity(uint length, uint8_t *dst, uint8_t *src);
struct des3_ctx
{
    des_ctx [3]des;
}
int  nettle_des3_set_key(des3_ctx *ctx, uint8_t *key);
void  nettle_des3_encrypt(des3_ctx *ctx, uint length, uint8_t *dst, uint8_t *src);
void  nettle_des3_decrypt(des3_ctx *ctx, uint length, uint8_t *dst, uint8_t *src);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const DES_KEY_SIZE = 8;
const DES_BLOCK_SIZE = 8;
const _DES_KEY_LENGTH = 32;
const DES3_KEY_SIZE = 24;
static if (__traits(compiles, typeof(DES_BLOCK_SIZE))) static if (!__traits(isStaticFunction, DES_BLOCK_SIZE)) static if (__traits(isPOD, typeof(DES_BLOCK_SIZE))) const DES3_BLOCK_SIZE = DES_BLOCK_SIZE;
