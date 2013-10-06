/* Converted to D from output/dsa.h by htod */
module nettle.dsa;
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
struct dsa_public_key
{
    mpz_t p;
    mpz_t q;
    mpz_t g;
    mpz_t y;
}
struct dsa_private_key
{
    mpz_t x;
}
struct dsa_signature
{
    mpz_t r;
    mpz_t s;
}
void  nettle_dsa_public_key_init(dsa_public_key *key);
void  nettle_dsa_public_key_clear(dsa_public_key *key);
void  nettle_dsa_private_key_init(dsa_private_key *key);
void  nettle_dsa_private_key_clear(dsa_private_key *key);
void  nettle_dsa_signature_init(dsa_signature *signature);
void  nettle_dsa_signature_clear(dsa_signature *signature);
int  nettle_dsa_sha1_sign(dsa_public_key *pub, dsa_private_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, sha1_ctx *hash, dsa_signature *signature);
int  nettle_dsa_sha256_sign(dsa_public_key *pub, dsa_private_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, sha256_ctx *hash, dsa_signature *signature);
int  nettle_dsa_sha1_verify(dsa_public_key *key, sha1_ctx *hash, dsa_signature *signature);
int  nettle_dsa_sha256_verify(dsa_public_key *key, sha256_ctx *hash, dsa_signature *signature);
int  nettle_dsa_sha1_sign_digest(dsa_public_key *pub, dsa_private_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, uint8_t *digest, dsa_signature *signature);
int  nettle_dsa_sha256_sign_digest(dsa_public_key *pub, dsa_private_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, uint8_t *digest, dsa_signature *signature);
int  nettle_dsa_sha1_verify_digest(dsa_public_key *key, uint8_t *digest, dsa_signature *signature);
int  nettle_dsa_sha256_verify_digest(dsa_public_key *key, uint8_t *digest, dsa_signature *signature);
int  nettle_dsa_generate_keypair(dsa_public_key *pub, dsa_private_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, void *progress_ctx, void  function(void *ctx, int c)progress, uint p_bits, uint q_bits);
int  nettle_dsa_keypair_to_sexp(nettle_buffer *buffer, char *algorithm_name, dsa_public_key *pub, dsa_private_key *priv);
int  nettle_dsa_signature_from_sexp(dsa_signature *rs, sexp_iterator *i, uint q_bits);
int  nettle_dsa_keypair_from_sexp_alist(dsa_public_key *pub, dsa_private_key *priv, uint p_max_bits, uint q_bits, sexp_iterator *i);
int  nettle_dsa_sha1_keypair_from_sexp(dsa_public_key *pub, dsa_private_key *priv, uint p_max_bits, uint length, uint8_t *expr);
int  nettle_dsa_sha256_keypair_from_sexp(dsa_public_key *pub, dsa_private_key *priv, uint p_max_bits, uint length, uint8_t *expr);
int  nettle_dsa_params_from_der_iterator(dsa_public_key *pub, uint p_max_bits, asn1_der_iterator *i);
int  nettle_dsa_public_key_from_der_iterator(dsa_public_key *pub, uint p_max_bits, asn1_der_iterator *i);
int  nettle_dsa_openssl_private_key_from_der_iterator(dsa_public_key *pub, dsa_private_key *priv, uint p_max_bits, asn1_der_iterator *i);
int  nettle_openssl_provate_key_from_der(dsa_public_key *pub, dsa_private_key *priv, uint p_max_bits, uint length, uint8_t *data);
int  _nettle_dsa_sign(dsa_public_key *pub, dsa_private_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, uint digest_size, uint8_t *digest, dsa_signature *signature);
int  _nettle_dsa_verify(dsa_public_key *key, uint digest_size, uint8_t *digest, dsa_signature *signature);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const SHA1_DIGEST_SIZE = 20;
const SHA1_DATA_SIZE = 64;
const _SHA1_DIGEST_LENGTH = 5;
const SHA256_DIGEST_SIZE = 32;
const SHA256_DATA_SIZE = 64;
const _SHA256_DIGEST_LENGTH = 8;
const SHA224_DIGEST_SIZE = 28;
const SHA512_DIGEST_SIZE = 64;
const SHA512_DATA_SIZE = 128;
const _SHA512_DIGEST_LENGTH = 8;
const SHA384_DIGEST_SIZE = 48;
const DSA_SHA1_MIN_P_BITS = 512;
const DSA_SHA1_Q_OCTETS = 20;
const DSA_SHA1_Q_BITS = 160;
const DSA_SHA256_MIN_P_BITS = 1024;
const DSA_SHA256_Q_OCTETS = 32;
const DSA_SHA256_Q_BITS = 256;
void main(){}
