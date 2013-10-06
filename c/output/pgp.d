/* Converted to D from output/pgp.h by htod */
module nettle.pgp;
struct _N1
{
}
extern (C):
alias _N1 __mpz_struct;
alias __mpz_struct [1]mpz_t;
alias int time_t;
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
struct nettle_cipher
{
    char *name;
    uint context_size;
    uint block_size;
    uint key_size;
    void  function(void *ctx, uint length, uint8_t *key)set_encrypt_key;
    void  function(void *ctx, uint length, uint8_t *key)set_decrypt_key;
    void  function(void *ctx, uint length, uint8_t *dst, uint8_t *src)encrypt;
    void  function(void *ctx, uint length, uint8_t *dst, uint8_t *src)decrypt;
}
extern const nettle_cipher *[]nettle_ciphers;
extern const nettle_cipher nettle_aes128;
extern const nettle_cipher nettle_aes192;
extern const nettle_cipher nettle_aes256;
extern const nettle_cipher nettle_arcfour128;
extern const nettle_cipher nettle_camellia128;
extern const nettle_cipher nettle_camellia192;
extern const nettle_cipher nettle_camellia256;
extern const nettle_cipher nettle_cast128;
extern const nettle_cipher nettle_serpent128;
extern const nettle_cipher nettle_serpent192;
extern const nettle_cipher nettle_serpent256;
extern const nettle_cipher nettle_twofish128;
extern const nettle_cipher nettle_twofish192;
extern const nettle_cipher nettle_twofish256;
extern const nettle_cipher nettle_arctwo40;
extern const nettle_cipher nettle_arctwo64;
extern const nettle_cipher nettle_arctwo128;
extern const nettle_cipher nettle_arctwo_gutmann128;
struct nettle_hash
{
    char *name;
    uint context_size;
    uint digest_size;
    uint block_size;
    void  function(void *ctx)init;
    void  function(void *ctx, uint length, uint8_t *src)update;
    void  function(void *ctx, uint length, uint8_t *dst)digest;
}
extern const nettle_hash *[]nettle_hashes;
extern const nettle_hash nettle_md2;
extern const nettle_hash nettle_md4;
extern const nettle_hash nettle_md5;
extern const nettle_hash nettle_gosthash94;
extern const nettle_hash nettle_ripemd160;
extern const nettle_hash nettle_sha1;
extern const nettle_hash nettle_sha224;
extern const nettle_hash nettle_sha256;
extern const nettle_hash nettle_sha384;
extern const nettle_hash nettle_sha512;
extern const nettle_hash nettle_sha3_224;
extern const nettle_hash nettle_sha3_256;
extern const nettle_hash nettle_sha3_384;
extern const nettle_hash nettle_sha3_512;
struct nettle_armor
{
    char *name;
    uint encode_context_size;
    uint decode_context_size;
    uint encode_final_length;
    void  function(void *ctx)encode_init;
    uint  function(uint length)encode_length;
    uint  function(void *ctx, uint8_t *dst, uint src_length, uint8_t *src)encode_update;
    uint  function(void *ctx, uint8_t *dst)encode_final;
    void  function(void *ctx)decode_init;
    uint  function(uint length)decode_length;
    int  function(void *ctx, uint *dst_length, uint8_t *dst, uint src_length, uint8_t *src)decode_update;
    int  function(void *ctx)decode_final;
}
extern const nettle_armor *[]nettle_armors;
extern const nettle_armor nettle_base64;
extern const nettle_armor nettle_base16;
uint  nettle_mpz_sizeinbase_256_s(__mpz_struct *x);
uint  nettle_mpz_sizeinbase_256_u(__mpz_struct *x);
void  nettle_mpz_get_str_256(uint length, uint8_t *s, __mpz_struct *x);
void  nettle_mpz_set_str_256_s(__mpz_struct *x, uint length, uint8_t *s);
void  nettle_mpz_init_set_str_256_s(__mpz_struct *x, uint length, uint8_t *s);
void  nettle_mpz_set_str_256_u(__mpz_struct *x, uint length, uint8_t *s);
void  nettle_mpz_init_set_str_256_u(__mpz_struct *x, uint length, uint8_t *s);
void  nettle_mpz_random_size(__mpz_struct *x, void *ctx, void  function(void *ctx, uint length, uint8_t *dst)random, uint bits);
void  nettle_mpz_random(__mpz_struct *x, void *ctx, void  function(void *ctx, uint length, uint8_t *dst)random, __mpz_struct *n);
void  nettle_next_prime(__mpz_struct *p, __mpz_struct *n, uint count, uint prime_limit, void *progress_ctx, void  function(void *ctx, int c)progress);
void  nettle_random_prime(__mpz_struct *p, uint bits, int top_bits_set, void *ctx, void  function(void *ctx, uint length, uint8_t *dst)random, void *progress_ctx, void  function(void *ctx, int c)progress);
void  _nettle_generate_pocklington_prime(__mpz_struct *p, __mpz_struct *r, uint bits, int top_bits_set, void *ctx, void  function(void *ctx, uint length, uint8_t *dst)random, __mpz_struct *p0, __mpz_struct *q, __mpz_struct *p0q);
int  nettle_mpz_set_sexp(__mpz_struct *x, uint limit, sexp_iterator *i);
int  nettle_asn1_der_get_bignum(asn1_der_iterator *iterator, __mpz_struct *x, uint max_bits);
int  nettle_pgp_put_uint32(nettle_buffer *buffer, uint32_t i);
int  nettle_pgp_put_uint16(nettle_buffer *buffer, uint i);
int  nettle_pgp_put_mpi(nettle_buffer *buffer, __mpz_struct *x);
int  nettle_pgp_put_string(nettle_buffer *buffer, uint length, uint8_t *s);
int  nettle_pgp_put_length(nettle_buffer *buffer, uint length);
int  nettle_pgp_put_header(nettle_buffer *buffer, uint tag, uint length);
void  nettle_pgp_put_header_length(nettle_buffer *buffer, uint start, uint field_size);
uint  nettle_pgp_sub_packet_start(nettle_buffer *buffer);
int  nettle_pgp_put_sub_packet(nettle_buffer *buffer, uint type, uint length, uint8_t *data);
void  nettle_pgp_sub_packet_end(nettle_buffer *buffer, uint start);
int  nettle_pgp_put_public_rsa_key(nettle_buffer *, rsa_public_key *key, time_t timestamp);
int  nettle_pgp_put_rsa_sha1_signature(nettle_buffer *buffer, rsa_private_key *key, uint8_t *keyid, uint type, sha1_ctx *hash);
int  nettle_pgp_put_userid(nettle_buffer *buffer, uint length, uint8_t *name);
uint32_t  nettle_pgp_crc24(uint length, uint8_t *data);
int  nettle_pgp_armor(nettle_buffer *buffer, char *tag, uint length, uint8_t *data);
enum pgp_lengths
{
    PGP_LENGTH_ONE_OCTET,
    PGP_LENGTH_TWO_OCTETS = 192,
    PGP_LENGTH_FOUR_OCTETS = 8384,
}
enum pgp_public_key_algorithm
{
    PGP_RSA = 1,
    PGP_RSA_ENCRYPT,
    PGP_RSA_SIGN,
    PGP_EL_GAMAL_ENCRYPT = 16,
    PGP_DSA,
    PGP_EL_GAMAL = 20,
}
enum pgp_symmetric_algorithm
{
    PGP_PLAINTEXT,
    PGP_IDEA,
    PGP_3DES,
    PGP_CAST5,
    PGP_BLOWFISH,
    PGP_SAFER_SK,
    PGP_AES128 = 7,
    PGP_AES192,
    PGP_AES256,
}
enum pgp_compression_algorithm
{
    PGP_UNCOMPRESSED,
    PGP_ZIP,
    PGP_ZLIB,
}
enum pgp_hash_algorithm
{
    PGP_MD5 = 1,
    PGP_SHA1,
    PGP_RIPEMD,
    PGP_MD2 = 5,
    PGP_TIGER192,
    PGP_HAVAL,
}
enum pgp_tag
{
    PGP_TAG_PUBLIC_SESSION_KEY = 1,
    PGP_TAG_SIGNATURE,
    PGP_TAG_SYMMETRIC_SESSION_KEY,
    PGP_TAG_ONE_PASS_SIGNATURE,
    PGP_TAG_SECRET_KEY,
    PGP_TAG_PUBLIC_KEY,
    PGP_TAG_SECRET_SUBKEY,
    PGP_TAG_COMPRESSED,
    PGP_TAG_ENCRYPTED,
    PGP_TAG_MARKER,
    PGP_TAG_LITERAL,
    PGP_TAG_TRUST,
    PGP_TAG_USERID,
    PGP_TAG_PUBLIC_SUBKEY,
}
enum pgp_signature_type
{
    PGP_SIGN_BINARY,
    PGP_SIGN_TEXT,
    PGP_SIGN_STANDALONE,
    PGP_SIGN_CERTIFICATION = 16,
    PGP_SIGN_CERTIFICATION_PERSONA,
    PGP_SIGN_CERTIFICATION_CASUAL,
    PGP_SIGN_CERTIFICATION_POSITIVE,
    PGP_SIGN_SUBKEY = 24,
    PGP_SIGN_KEY = 31,
    PGP_SIGN_REVOCATION,
    PGP_SIGN_REVOCATION_SUBKEY = 40,
    PGP_SIGN_REVOCATION_CERTIFICATE = 48,
    PGP_SIGN_TIMESTAMP = 64,
}
enum pgp_subpacket_tag
{
    PGP_SUBPACKET_CREATION_TIME = 2,
    PGP_SUBPACKET_SIGNATURE_EXPIRATION_TIME,
    PGP_SUBPACKET_EXPORTABLE_CERTIFICATION,
    PGP_SUBPACKET_TRUST_SIGNATURE,
    PGP_SUBPACKET_REGULAR_EXPRESSION,
    PGP_SUBPACKET_REVOCABLE,
    PGP_SUBPACKET_KEY_EXPIRATION_TIME = 9,
    PGP_SUBPACKET_PLACEHOLDER,
    PGP_SUBPACKET_PREFERRED_SYMMETRIC_ALGORITHMS,
    PGP_SUBPACKET_REVOCATION_KEY,
    PGP_SUBPACKET_ISSUER_KEY_ID = 16,
    PGP_SUBPACKET_NOTATION_DATA = 20,
    PGP_SUBPACKET_PREFERRED_HASH_ALGORITHMS,
    PGP_SUBPACKET_PREFERRED_COMPRESSION_ALGORITHMS,
    PGP_SUBPACKET_KEY_SERVER_PREFERENCES,
    PGP_SUBPACKET_PREFERRED_KEY_SERVER,
    PGP_SUBPACKET_PRIMARY_USER_ID,
    PGP_SUBPACKET_POLICY_URL,
    PGP_SUBPACKET_KEY_FLAGS,
    PGP_SUBPACKET_SIGNERS_USER_ID,
    PGP_SUBPACKET_REASON_FOR_REVOCATION,
}
struct rsa_public_key
{
}
struct rsa_private_key
{
}
struct sha1_ctx
{
}
struct nettle_buffer;
struct sexp_iterator;
struct asn1_der_iterator;
const unix = 1;
const _STDINT_HAVE_INT_FAST32_T = 1;
const __NETTLE_STDINT_H = 1;
const _GENERATED_STDINT_H = " ";
const _STDINT_HAVE_STDINT_H = 1;
void main(){}
