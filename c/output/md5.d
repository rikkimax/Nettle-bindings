/* Converted to D from output/md5.h by htod */
module nettle.md5;
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
struct md5_ctx
{
    uint32_t [4]state;
    uint32_t count_low;
    uint32_t count_high;
    uint8_t [64]block;
    uint index;
}
void  nettle_md5_init(md5_ctx *ctx);
void  nettle_md5_update(md5_ctx *ctx, uint length, uint8_t *data);
void  nettle_md5_digest(md5_ctx *ctx, uint length, uint8_t *digest);
void  _nettle_md5_compress(uint32_t *state, uint8_t *data);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const MD5_DIGEST_SIZE = 16;
const MD5_DATA_SIZE = 64;
const _MD5_DIGEST_LENGTH = 4;
void main(){}
