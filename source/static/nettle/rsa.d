/* Converted to D from output/rsa.h by htod */
module nettle.rsa;
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
struct rsa_public_key
{
    uint size;
    mpz_t n;
    mpz_t e;
}
struct rsa_private_key
{
    uint size;
    mpz_t d;
    mpz_t p;
    mpz_t q;
    mpz_t a;
    mpz_t b;
    mpz_t c;
}
void  nettle_rsa_public_key_init(rsa_public_key *key);
void  nettle_rsa_public_key_clear(rsa_public_key *key);
int  nettle_rsa_public_key_prepare(rsa_public_key *key);
void  nettle_rsa_private_key_init(rsa_private_key *key);
void  nettle_rsa_private_key_clear(rsa_private_key *key);
int  nettle_rsa_private_key_prepare(rsa_private_key *key);
int  nettle_rsa_pkcs1_sign(rsa_private_key *key, uint length, uint8_t *digest_info, __mpz_struct *s);
int  nettle_rsa_pkcs1_sign_tr(rsa_public_key *pub, rsa_private_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, uint length, uint8_t *digest_info, __mpz_struct *s);
int  nettle_rsa_pkcs1_verify(rsa_public_key *key, uint length, uint8_t *digest_info, __mpz_struct *signature);
int  nettle_rsa_md5_sign(rsa_private_key *key, md5_ctx *hash, __mpz_struct *signature);
int  nettle_rsa_md5_verify(rsa_public_key *key, md5_ctx *hash, __mpz_struct *signature);
int  nettle_rsa_sha1_sign(rsa_private_key *key, sha1_ctx *hash, __mpz_struct *signature);
int  nettle_rsa_sha1_verify(rsa_public_key *key, sha1_ctx *hash, __mpz_struct *signature);
int  nettle_rsa_sha256_sign(rsa_private_key *key, sha256_ctx *hash, __mpz_struct *signature);
int  nettle_rsa_sha256_verify(rsa_public_key *key, sha256_ctx *hash, __mpz_struct *signature);
int  nettle_rsa_sha512_sign(rsa_private_key *key, sha512_ctx *hash, __mpz_struct *signature);
int  nettle_rsa_sha512_verify(rsa_public_key *key, sha512_ctx *hash, __mpz_struct *signature);
int  nettle_rsa_md5_sign_digest(rsa_private_key *key, uint8_t *digest, __mpz_struct *s);
int  nettle_rsa_md5_verify_digest(rsa_public_key *key, uint8_t *digest, __mpz_struct *signature);
int  nettle_rsa_sha1_sign_digest(rsa_private_key *key, uint8_t *digest, __mpz_struct *s);
int  nettle_rsa_sha1_verify_digest(rsa_public_key *key, uint8_t *digest, __mpz_struct *signature);
int  nettle_rsa_sha256_sign_digest(rsa_private_key *key, uint8_t *digest, __mpz_struct *s);
int  nettle_rsa_sha256_verify_digest(rsa_public_key *key, uint8_t *digest, __mpz_struct *signature);
int  nettle_rsa_sha512_sign_digest(rsa_private_key *key, uint8_t *digest, __mpz_struct *s);
int  nettle_rsa_sha512_verify_digest(rsa_public_key *key, uint8_t *digest, __mpz_struct *signature);
int  nettle_rsa_encrypt(rsa_public_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, uint length, uint8_t *cleartext, __mpz_struct *cipher);
int  nettle_rsa_decrypt(rsa_private_key *key, uint *length, uint8_t *cleartext, __mpz_struct *ciphertext);
int  nettle_rsa_decrypt_tr(rsa_public_key *pub, rsa_private_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, uint *length, uint8_t *message, __mpz_struct *gibberish);
void  nettle_rsa_compute_root(rsa_private_key *key, __mpz_struct *x, __mpz_struct *m);
int  nettle_rsa_generate_keypair(rsa_public_key *pub, rsa_private_key *key, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, void *progress_ctx, void  function(void *ctx, int c)progress, uint n_size, uint e_size);
int  nettle_rsa_keypair_to_sexp(nettle_buffer *buffer, char *algorithm_name, rsa_public_key *pub, rsa_private_key *priv);
int  nettle_rsa_keypair_from_sexp_alist(rsa_public_key *pub, rsa_private_key *priv, uint limit, sexp_iterator *i);
int  nettle_rsa_keypair_from_sexp(rsa_public_key *pub, rsa_private_key *priv, uint limit, uint length, uint8_t *expr);
int  nettle_rsa_public_key_from_der_iterator(rsa_public_key *pub, uint limit, asn1_der_iterator *i);
int  nettle_rsa_private_key_from_der_iterator(rsa_public_key *pub, rsa_private_key *priv, uint limit, asn1_der_iterator *i);
int  nettle_rsa_keypair_from_der(rsa_public_key *pub, rsa_private_key *priv, uint limit, uint length, uint8_t *data);
int  nettle_rsa_keypair_to_openpgp(nettle_buffer *buffer, rsa_public_key *pub, rsa_private_key *priv, char *userid);
int  _nettle_rsa_verify(rsa_public_key *key, __mpz_struct *m, __mpz_struct *s);
uint  _nettle_rsa_check_size(__mpz_struct *n);
void  _nettle_rsa_blind(rsa_public_key *pub, void *random_ctx, void  function(void *ctx, uint length, uint8_t *dst)random, __mpz_struct *c, __mpz_struct *ri);
void  _nettle_rsa_unblind(rsa_public_key *pub, __mpz_struct *c, __mpz_struct *ri);
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const MD5_DIGEST_SIZE = 16;
const MD5_DATA_SIZE = 64;
const _MD5_DIGEST_LENGTH = 4;
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
const RSA_MINIMUM_N_OCTETS = 12;
