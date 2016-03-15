/*
 * encrypt.c - Manage the global encryptor
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>

#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/md5.h>
#include <openssl/rand.h>

#elif defined(USE_CRYPTO_POLARSSL)

#include <polarssl/md5.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/version.h>
#define CIPHER_UNSUPPORTED "unsupported"

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

#endif

// #include <sodium.h>

#include "encrypt.h"

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

#ifdef DEBUG
static void dump(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++) {
        printf("0x%02x ", (uint8_t)text[i]);
    }
    printf("\n");
}
#endif

static const char * supported_ciphers[] =
{
    "table",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
//    "salsa20",
//    "chacha20"
};

#ifdef USE_CRYPTO_POLARSSL
static const char * supported_ciphers_polarssl[] =
{
    "table",
    "ARC4-128",
    "ARC4-128",
    "AES-128-CFB128",
    "AES-192-CFB128",
    "AES-256-CFB128",
    "BLOWFISH-CFB64",
    "CAMELLIA-128-CFB128",
    "CAMELLIA-192-CFB128",
    "CAMELLIA-256-CFB128",
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
//    "salsa20",
//    "chacha20"
};
#endif

#ifdef USE_CRYPTO_APPLECC
static const CCAlgorithm supported_ciphers_applecc[] =
{
    kCCAlgorithmInvalid,
    kCCAlgorithmRC4,
    kCCAlgorithmRC4,
    kCCAlgorithmAES,
    kCCAlgorithmAES,
    kCCAlgorithmAES,
    kCCAlgorithmBlowfish,
    kCCAlgorithmInvalid,
    kCCAlgorithmInvalid,
    kCCAlgorithmInvalid,
    kCCAlgorithmCAST,
    kCCAlgorithmDES,
    kCCAlgorithmInvalid,
    kCCAlgorithmRC2,
    kCCAlgorithmInvalid,
//    kCCAlgorithmInvalid,
//    kCCAlgorithmInvalid
};

#endif

static const int supported_ciphers_iv_size[] =
{
    0, 0, 16, 16, 16, 16, 8, 16, 16, 16, 8, 8, 8, 8, 16//, 8, 8
};

static const int supported_ciphers_key_size[] =
{
    0, 16, 16, 16, 24, 32, 16, 16, 24, 32, 16, 8, 16, 16, 16//, 32, 32
};

#define CIPHER_NUM (sizeof(supported_ciphers)/sizeof(supported_ciphers[0]))

static int crypto_stream_xor_ic(uint8_t *c, const uint8_t *m, uint64_t mlen,
                                const uint8_t *n, uint64_t ic, const uint8_t *k,
                                int method)
{
/*
    switch (method) {
    case SALSA20:
        return crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k);
    case CHACHA20:
        return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k);
    }
*/    
    // always return 0
    return 0;
}

static int random_compare(const void *_x, const void *_y, uint32_t i,
                          uint64_t a)
{
    uint8_t x = *((uint8_t *)_x);
    uint8_t y = *((uint8_t *)_y);
    return a % (x + i) - a % (y + i);
}

static void merge(uint8_t *left, int llength, uint8_t *right,
                  int rlength, uint32_t salt, uint64_t key)
{
    uint8_t *ltmp = (uint8_t *)malloc(llength * sizeof(uint8_t));
    uint8_t *rtmp = (uint8_t *)malloc(rlength * sizeof(uint8_t));

    uint8_t *ll = ltmp;
    uint8_t *rr = rtmp;

    uint8_t *result = left;

    memcpy(ltmp, left, llength * sizeof(uint8_t));
    memcpy(rtmp, right, rlength * sizeof(uint8_t));

    while (llength > 0 && rlength > 0) {
        if (random_compare(ll, rr, salt, key) <= 0) {
            *result = *ll;
            ++ll;
            --llength;
        } else {
            *result = *rr;
            ++rr;
            --rlength;
        }
        ++result;
    }

    if (llength > 0) {
        while (llength > 0) {
            *result = *ll;
            ++result;
            ++ll;
            --llength;
        }
    } else {
        while (rlength > 0) {
            *result = *rr;
            ++result;
            ++rr;
            --rlength;
        }
    }

    free(ltmp);
    free(rtmp);
}

static void merge_sort(uint8_t array[], int length,
                       uint32_t salt, uint64_t key)
{
    uint8_t middle;
    uint8_t *left, *right;
    int llength;

    if (length <= 1) {
        return;
    }

    middle = length / 2;

    llength = length - middle;

    left = array;
    right = array + llength;

    merge_sort(left, llength, salt, key);
    merge_sort(right, middle, salt, key);
    merge(left, llength, right, middle, salt, key);
}

static unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md)
{
#if defined(USE_CRYPTO_OPENSSL)
    return MD5(d, n, md);
#elif defined(USE_CRYPTO_POLARSSL)
    static unsigned char m[16];
    if (md == NULL) {
        md = m;
    }
    md5(d, n, md);
    return md;
#endif
}

static void enc_table_init(enc_info * info, const char *pass)
{
    uint32_t i;
    uint64_t key = 0;
    uint8_t *digest;

    info->enc_table = malloc(256);
    info->dec_table = malloc(256);

    digest = enc_md5((const uint8_t *)pass, strlen(pass), NULL);

    for (i = 0; i < 8; i++) {
        key += OFFSET_ROL(digest, i);
    }

    for (i = 0; i < 256; ++i) {
        info->enc_table[i] = i;
    }
    for (i = 1; i < 1024; ++i) {
        merge_sort(info->enc_table, 256, i, key);
    }
    for (i = 0; i < 256; ++i) {
        // gen decrypt table from encrypt table
        info->dec_table[info->enc_table[i]] = i;
    }
}

int cipher_iv_size(const cipher_kt_t *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CIPHER_iv_length(cipher);
#elif defined(USE_CRYPTO_POLARSSL)
    if (cipher == NULL) {
        return 0;
    }
    return cipher->iv_size;
#endif
}

int cipher_key_size(const cipher_kt_t *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CIPHER_key_length(cipher);
#elif defined(USE_CRYPTO_POLARSSL)
    if (cipher == NULL) {
        return 0;
    }
    /* Override PolarSSL 32 bit default key size with sane 128 bit default */
    if (cipher->base != NULL && POLARSSL_CIPHER_ID_BLOWFISH ==
        cipher->base->cipher) {
        return 128 / 8;
    }
    return cipher->key_length / 8;
#endif
}

int bytes_to_key(const cipher_kt_t *cipher, const digest_type_t *md,
                 const uint8_t *pass, uint8_t *key, uint8_t *iv)
{
    size_t datal;
    datal = strlen((const char *)pass);
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_BytesToKey(cipher, md, NULL, pass, datal, 1, key, iv);
#elif defined(USE_CRYPTO_POLARSSL)
    md_context_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    int niv;
    int nkey;
    int addmd;
    unsigned int mds;
    unsigned int i;
    int rv;

    nkey = cipher_key_size(cipher);
    niv = cipher_iv_size(cipher);
    rv = nkey;
    if (pass == NULL) {
        return nkey;
    }

    memset(&c, 0, sizeof(md_context_t));
    if (md_init_ctx(&c, md)) {
        return 0;
    }
    addmd = 0;
    mds = md_get_size(md);
    for (;; ) {
        int error;
        do {
            error = 1;
            if (md_starts(&c)) {
                break;
            }
            if (addmd) {
                if (md_update(&c, &(md_buf[0]), mds)) {
                    break;
                }
            } else {
                addmd = 1;
            }
            if (md_update(&c, pass, datal)) {
                break;
            }
            if (md_finish(&c, &(md_buf[0]))) {
                break;
            }
            error = 0;
        } while (0);
        if (error) {
            md_free_ctx(&c);
            memset(md_buf, 0, MAX_MD_SIZE);
            return 0;
        }

        i = 0;
        if (nkey) {
            for (;; ) {
                if (nkey == 0) {
                    break;
                }
                if (i == mds) {
                    break;
                }
                if (key != NULL) {
                    *(key++) = md_buf[i];
                }
                nkey--;
                i++;
            }
        }
        if (niv && (i != mds)) {
            for (;; ) {
                if (niv == 0) {
                    break;
                }
                if (i == mds) {
                    break;
                }
                if (iv != NULL) {
                    *(iv++) = md_buf[i];
                }
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0)) {
            break;
        }
    }
    md_free_ctx(&c);
    memset(md_buf, 0, MAX_MD_SIZE);
    return rv;
#endif
}

int rand_bytes(uint8_t *output, int len)
{
#if defined(USE_CRYPTO_OPENSSL)
    return RAND_bytes(output, len);
#elif defined(USE_CRYPTO_POLARSSL)
    static entropy_context ec = {};
    static ctr_drbg_context cd_ctx = {};
    static unsigned char rand_initialised = 0;
    const size_t blen = min(len, CTR_DRBG_MAX_REQUEST);

    if (!rand_initialised) {
#ifdef _WIN32
        HCRYPTPROV hProvider;
        union {
            unsigned __int64 seed;
            BYTE buffer[8];
        } rand_buffer;

        hProvider = 0;
        if (CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, \
                                CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            CryptGenRandom(hProvider, 8, rand_buffer.buffer);
            CryptReleaseContext(hProvider, 0);
        } else {
            rand_buffer.seed = (unsigned __int64)clock();
        }
#else
        FILE *urand;
        union {
            uint64_t seed;
            uint8_t buffer[8];
        } rand_buffer;

        urand = fopen("/dev/urandom", "r");
        if (urand) {
            int read = fread(&rand_buffer.seed, sizeof(rand_buffer.seed), 1,
                             urand);
            fclose(urand);
            if (read <= 0) {
                rand_buffer.seed = (uint64_t)clock();
            }
        } else {
            rand_buffer.seed = (uint64_t)clock();
        }
#endif
        entropy_init(&ec);
        if (ctr_drbg_init(&cd_ctx, entropy_func, &ec,
                          (const unsigned char *)rand_buffer.buffer, 8) != 0) {
#if POLARSSL_VERSION_NUMBER >= 0x01030000
            entropy_free(&ec);
#endif
            //FATAL("Failed to initialize random generator");
        }
        rand_initialised = 1;
    }
    while (len > 0) {
        if (ctr_drbg_random(&cd_ctx, output, blen) != 0) {
            return 0;
        }
        output += blen;
        len -= blen;
    }
    return 1;
#endif
}

const cipher_kt_t *get_cipher_type(int method)
{
    if (method <= TABLE || method >= CIPHER_NUM) {
        //LOGE("get_cipher_type(): Illegal method");
        return NULL;
    }

    if (method == RC4_MD5) {
        method = RC4;
    }
/*
    if (method >= SALSA20) {
        return NULL;
    }
*/
    const char *ciphername = supported_ciphers[method];
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_get_cipherbyname(ciphername);
#elif defined(USE_CRYPTO_POLARSSL)
    const char *polarname = supported_ciphers_polarssl[method];
    if (strcmp(polarname, CIPHER_UNSUPPORTED) == 0) {
        //LOGE("Cipher %s currently is not supported by PolarSSL library",
        //     ciphername);
        return NULL;
    }
    return cipher_info_from_string(polarname);
#endif
}

const digest_type_t *get_digest_type(const char *digest)
{
    if (digest == NULL) {
        //LOGE("get_digest_type(): Digest name is null");
        return NULL;
    }

#if defined(USE_CRYPTO_OPENSSL)
    return EVP_get_digestbyname(digest);
#elif defined(USE_CRYPTO_POLARSSL)
    return md_info_from_string(digest);
#endif
}

static int cipher_context_init(const enc_info * info, cipher_ctx_t *ctx, int enc)
{
    int method = info->method;
    if (method <= TABLE || method >= CIPHER_NUM) {
        // Illegal method
        return -1;
    }
/*
    if (method >= SALSA20) {
        enc_iv_len = supported_ciphers_iv_size[method];
        return;
    }
*/
    const char *ciphername = supported_ciphers[method];
#if defined(USE_CRYPTO_APPLECC)
    cipher_cc_t *cc = &ctx->cc;
    cc->cryptor = NULL;
    cc->cipher = supported_ciphers_applecc[method];
    if (cc->cipher == kCCAlgorithmInvalid) {
        cc->valid = kCCContextInvalid;
    } else {
        cc->valid = kCCContextValid;
        if (cc->cipher == kCCAlgorithmRC4) {
            cc->mode = kCCModeRC4;
            cc->padding = ccNoPadding;
        } else {
            cc->mode = kCCModeCFB;
            cc->padding = ccPKCS7Padding;
        }
        return 0;
    }
#endif

    cipher_evp_t *evp = &ctx->evp;
    const cipher_kt_t *cipher = get_cipher_type(method);
#if defined(USE_CRYPTO_OPENSSL)
    if (cipher == NULL) {
        // Cipher is not found in OpenSSL library
        return -1;
    }
    EVP_CIPHER_CTX_init(evp);
    if (!EVP_CipherInit_ex(evp, cipher, NULL, NULL, NULL, enc)) {
        // annot initialize cipher
        return -1; 
    }
    if (!EVP_CIPHER_CTX_set_key_length(evp, info->key_len)) {
        EVP_CIPHER_CTX_cleanup(evp);
        // Invalid key length
        return -1;
    }
    if (method > RC4_MD5) {
        EVP_CIPHER_CTX_set_padding(evp, 1);
    }
#elif defined(USE_CRYPTO_POLARSSL)
    if (cipher == NULL) {
        // Cipher is not found in PolarSSL library
        return -1;
    }
    if (cipher_init_ctx(evp, cipher) != 0) {
        // Cannot initialize PolarSSL cipher context
        return -1;
    }
#endif
    return 0;
}

static void cipher_context_set_iv(const enc_info * info, cipher_ctx_t *ctx, uint8_t *iv, size_t iv_len,
                           int enc)
{
    const unsigned char *true_key;

    if (iv == NULL) {
        //LOGE("cipher_context_set_iv(): IV is null");
        return;
    }

    if (enc) {
        rand_bytes(iv, iv_len);
    }
/*
    if (enc_method >= SALSA20) {
        memcpy(ctx->iv, iv, iv_len);
        return;
    }
*/
    if (info->method == RC4_MD5) {
        unsigned char key_iv[32];
        memcpy(key_iv, info->key, 16);
        memcpy(key_iv + 16, iv, 16);
        true_key = enc_md5(key_iv, 32, NULL);
        iv_len = 0;
    } else {
        true_key = info->key;
    }

#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t *cc = &ctx->cc;
    if (cc->valid == kCCContextValid) {
        memcpy(cc->iv, iv, iv_len);
        memcpy(cc->key, true_key, info->key_len);
        cc->iv_len = iv_len;
        cc->key_len = info->key_len;
        cc->encrypt = enc ? kCCEncrypt : kCCDecrypt;
        if (cc->cryptor != NULL) {
            CCCryptorRelease(cc->cryptor);
            cc->cryptor = NULL;
        }

        CCCryptorStatus ret;
        ret = CCCryptorCreateWithMode(
            cc->encrypt,
            cc->mode,
            cc->cipher,
            cc->padding,
            cc->iv, cc->key, cc->key_len,
            NULL, 0, 0, 0,
            &cc->cryptor);
        if (ret != kCCSuccess) {
            if (cc->cryptor != NULL) {
                CCCryptorRelease(cc->cryptor);
                cc->cryptor = NULL;
            }
            //FATAL("Cannot set CommonCrypto key and IV");
        }
        return;
    }
#endif

    cipher_evp_t *evp = &ctx->evp;
    if (evp == NULL) {
        //LOGE("cipher_context_set_iv(): Cipher context is null");
        return;
    }
#if defined(USE_CRYPTO_OPENSSL)
    if (!EVP_CipherInit_ex(evp, NULL, NULL, true_key, iv, enc)) {
        EVP_CIPHER_CTX_cleanup(evp);
        //FATAL("Cannot set key and IV");
    }
#elif defined(USE_CRYPTO_POLARSSL)
    if (cipher_setkey(evp, true_key, info->key_len * 8, enc) != 0) {
        cipher_free_ctx(evp);
        //FATAL("Cannot set PolarSSL cipher key");
    }
#if POLARSSL_VERSION_NUMBER >= 0x01030000
    if (cipher_set_iv(evp, iv, iv_len) != 0) {
        cipher_free_ctx(evp);
        //FATAL("Cannot set PolarSSL cipher IV");
    }
    if (cipher_reset(evp) != 0) {
        cipher_free_ctx(evp);
        //FATAL("Cannot finalize PolarSSL cipher context");
    }
#else
    if (cipher_reset(evp, iv) != 0) {
        cipher_free_ctx(evp);
        //FATAL("Cannot set PolarSSL cipher IV");
    }
#endif
#endif

#ifdef DEBUG
    dump("IV", (char *)iv, iv_len);
#endif
}

static void cipher_context_release(enc_info * info, cipher_ctx_t *ctx)
{
    if (info->method >= SALSA20) {
        return;
    }

#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t *cc = &ctx->cc;
    if (cc->cryptor != NULL) {
        CCCryptorRelease(cc->cryptor);
        cc->cryptor = NULL;
    }
    if (cc->valid == kCCContextValid) {
        return;
    }
#endif

    cipher_evp_t *evp = &ctx->evp;
#if defined(USE_CRYPTO_OPENSSL)
    EVP_CIPHER_CTX_cleanup(evp);
#elif defined(USE_CRYPTO_POLARSSL)
    cipher_free_ctx(evp);
#endif
}

static int cipher_context_update(cipher_ctx_t *ctx, uint8_t *output, int *olen,
                                 const uint8_t *input, int ilen)
{
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t *cc = &ctx->cc;
    if (cc->valid == kCCContextValid) {
        CCCryptorStatus ret;
        ret = CCCryptorUpdate(cc->cryptor, input, ilen, output,
                              ilen, (size_t *)olen);
        return (ret == kCCSuccess) ? 1 : 0;
    }
#endif
    cipher_evp_t *evp = &ctx->evp;
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CipherUpdate(evp, (uint8_t *)output, olen,
                            (const uint8_t *)input, (size_t)ilen);
#elif defined(USE_CRYPTO_POLARSSL)
    return !cipher_update(evp, (const uint8_t *)input, (size_t)ilen,
                          (uint8_t *)output, (size_t *)olen);
#endif
}

/* Calculate buffer size required for encrypt/decrypt data */
size_t ss_calc_buffer_size(struct enc_ctx * ctx, size_t ilen)
{
    int method = ctx->info->method;
    const cipher_kt_t *cipher = get_cipher_type(method);
#if defined(USE_CRYPTO_OPENSSL)
    if (ctx->init)
        return ilen + EVP_CIPHER_block_size(cipher); 
    else
        return EVP_CIPHER_iv_length(cipher) + ilen + EVP_CIPHER_block_size(cipher); 
#elif defined(USE_CRYPTO_POLARSSL)
    if (cipher == NULL) {
        return ilen;
    }
    if (ctx->init)
        return ilen + cipher_get_block_size(cipher); 
    else
        return cipher->iv_size + ilen + cipher_get_block_size(cipher); 
#endif
}

int ss_encrypt(struct enc_ctx *ctx, char *plaintext, size_t plen,
                  char * ciphertext, size_t * clen)
{
    if (ctx != NULL) {
        int err = 1;
        int iv_len = 0;
        int p_len = plen, c_len = plen;
        if (!ctx->init) {
            iv_len = ctx->info->iv_len;
        }

        if (!ctx->init) {
            uint8_t iv[MAX_IV_LENGTH];
            cipher_context_set_iv(ctx->info, &ctx->evp, iv, iv_len, 1);
            memcpy(ciphertext, iv, iv_len);
            ctx->counter = 0;
            ctx->init = 1;
        }

        if (ctx->info->method >= SALSA20) {
/*        
            int padding = ctx->counter % SODIUM_BLOCK_SIZE;
            if (buf_len < iv_len + padding + c_len) {
                buf_len = max(iv_len + (padding + c_len) * 2, buf_size);
                ciphertext = realloc(ciphertext, buf_len);
                tmp_len = buf_len;
                tmp_buf = ciphertext;
            }
            if (padding) {
                plaintext = realloc(plaintext, max(p_len + padding, buf_size));
                memmove(plaintext + padding, plaintext, p_len);
                memset(plaintext, 0, padding);
            }
            crypto_stream_xor_ic((uint8_t *)(ciphertext + iv_len),
                                 (const uint8_t *)plaintext,
                                 (uint64_t)(p_len + padding),
                                 (const uint8_t *)ctx->evp.iv,
                                 ctx->counter / SODIUM_BLOCK_SIZE, enc_key,
                                 enc_method);
            ctx->counter += p_len;
            if (padding) {
                memmove(ciphertext + iv_len, ciphertext + iv_len + padding,
                        c_len);
            }
*/            
        } else {
            err =
                cipher_context_update(&ctx->evp,
                                      (uint8_t *)(ciphertext + iv_len),
                                      &c_len, (const uint8_t *)plaintext,
                                      p_len);
            if (!err) {
                return 0;
            }
        }

#ifdef DEBUG
        dump("PLAIN", plaintext, p_len);
        dump("CIPHER", ciphertext + iv_len, c_len);
#endif

        *clen = iv_len + c_len;
        return 1;
    } else {
        char *begin = plaintext;
        while (plaintext < begin + plen) {
            *ciphertext = (char)ctx->info->enc_table[(uint8_t)*plaintext];
            plaintext++;
            ciphertext++;
        }
        *clen = plen;
        return 1;
    }
}

/* You need to ensure you have enough output buffer allocated */
int ss_decrypt(struct enc_ctx *ctx, char *ciphertext, size_t clen,
                 char *plaintext, size_t *olen)
{
    if (ctx != NULL) {
        int p_len = clen;
        int iv_len = 0;
        int err = 1;

        if (!ctx->init) {
            iv_len = ctx->info->iv_len;
            p_len -= iv_len;
            cipher_context_set_iv(ctx->info, &ctx->evp, (uint8_t *)ciphertext, iv_len, 0);
            ctx->counter = 0;
            ctx->init = 1;
        }

        if (ctx->info->method >= SALSA20) {
/*        
            int padding = ctx->counter % SODIUM_BLOCK_SIZE;
            if (buf_len < (p_len + padding) * 2) {
                buf_len = max((p_len + padding) * 2, buf_size);
                plaintext = realloc(plaintext, buf_len);
                tmp_len = buf_len;
                tmp_buf = plaintext;
            }
            if (padding) {
                ciphertext =
                    realloc(ciphertext, max(c_len + padding, buf_size));
                memmove(ciphertext + iv_len + padding, ciphertext + iv_len,
                        c_len - iv_len);
                memset(ciphertext + iv_len, 0, padding);
            }
            crypto_stream_xor_ic((uint8_t *)plaintext,
                                 (const uint8_t *)(ciphertext + iv_len),
                                 (uint64_t)(c_len - iv_len + padding),
                                 (const uint8_t *)ctx->evp.iv,
                                 ctx->counter / SODIUM_BLOCK_SIZE, enc_key,
                                 enc_method);
            ctx->counter += c_len - iv_len;
            if (padding) {
                memmove(plaintext, plaintext + padding, p_len);
            }
*/            
        } else {
            err = cipher_context_update(&ctx->evp, (uint8_t *)plaintext, &p_len,
                                        (const uint8_t *)(ciphertext + iv_len),
                                        clen - iv_len);
        }

        if (!err) {
//            free(ciphertext);
            return 0;
        }

        *olen = p_len;

        return 1;
    } else {
        char *begin = ciphertext;
        while (ciphertext < begin + clen) {
            *plaintext = (char)ctx->info->dec_table[(uint8_t)*ciphertext];
            ciphertext++;
            plaintext++;
        }
        *olen = clen;
        return 1;
    }
}

int enc_ctx_init(enc_info * info, struct enc_ctx *ctx, int enc)
{
    memset(ctx, 0, sizeof(struct enc_ctx));
    ctx->info = info;
    return cipher_context_init(info, &ctx->evp, enc);
}

void enc_ctx_free(struct enc_ctx *ctx)
{
    cipher_context_release(ctx->info, &ctx->evp);
}

static int enc_key_init(enc_info * info, int method, const char *pass)
{
    if (method <= TABLE || method >= CIPHER_NUM)
        return -1;

#if defined(USE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif

    uint8_t iv[MAX_IV_LENGTH];

    cipher_kt_t *cipher = NULL;
    cipher_kt_t cipher_info;


    if (method == SALSA20 || method == CHACHA20) {
/*    
        if (sodium_init() == -1) {
            //FATAL("Failed to initialize sodium");
        }
        // Fake cipher
        cipher = (cipher_kt_t *)&cipher_info;
#if defined(USE_CRYPTO_OPENSSL)
        cipher->key_len = supported_ciphers_key_size[method];
        cipher->iv_len = supported_ciphers_iv_size[method];
#endif
#if defined(USE_CRYPTO_POLARSSL)
        cipher->base = NULL;
        cipher->key_length = supported_ciphers_key_size[method] * 8;
        cipher->iv_size = supported_ciphers_iv_size[method];
#endif
*/
    } else {
        cipher = (cipher_kt_t *)get_cipher_type(method);
    }

    if (cipher == NULL) {
        do {
#if defined(USE_CRYPTO_POLARSSL) && defined(USE_CRYPTO_APPLECC)
            if (supported_ciphers_applecc[method] != kCCAlgorithmInvalid) {
                cipher_info.base = NULL;
                cipher_info.key_length = supported_ciphers_key_size[method] * 8;
                cipher_info.iv_size = supported_ciphers_iv_size[method];
                cipher = (cipher_kt_t *)&cipher_info;
                break;
            }
#endif
            return -1;
        } while (0);
    }

    const digest_type_t *md = get_digest_type("MD5");
    if (md == NULL)
        return -1;

    info->key_len = bytes_to_key(cipher, md, (const uint8_t *)pass, info->key, iv);
    if (info->key_len == 0) {
        //FATAL("Cannot generate key and IV");
        return -1;
    }
    if (method == RC4_MD5) {
        info->iv_len = 16;
    } else {
        info->iv_len = cipher_iv_size(cipher);
    }
    info->method = method;
    return method;
}

int enc_init(enc_info * info, const char *pass, const char *method)
{
    memset((void *)info, 0, sizeof(enc_info));
    int m = TABLE;
    if (method != NULL) {
        for (m = TABLE; m < CIPHER_NUM; m++) {
            if (strcmp(method, supported_ciphers[m]) == 0) {
                break;
            }
        }
        if (m >= CIPHER_NUM)
            // Invalid encryption method
            return -1;
    }
    if (m == TABLE) {
        enc_table_init(info, pass);
    } else {
        m = enc_key_init(info, m, pass);
    }
    return m;
}

void enc_free(enc_info * info)
{
    if (info->enc_table)
    {
        free(info->enc_table);
        info->enc_table = NULL;
    }
    if (info->dec_table)
    {
        free(info->dec_table);
        info->dec_table = NULL;
    }

}
