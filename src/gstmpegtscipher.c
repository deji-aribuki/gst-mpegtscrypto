/* GStMpegTSCrypto
 * Copyright (C) <2020> Deji Aribuki <daribuki@ketulabs.ch>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h> 

#ifdef HAVE_LIBDVBCSA
#include <dvbcsa/dvbcsa.h>
#endif

#include <gst/gst.h>
#include "gstmpegtscipher.h"

int aes_cbc_cs_encrypt(MpegTSCryptoCipher *c, uint8_t *in,
		int len, uint8_t *out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    uint8_t last_block[16] = {0};
    uint8_t temp[16] = {0};
    int i;
    int out_len = 0, final_len = 0;
    int no_residuals = len % 16;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 16) {
        cipher = EVP_aes_128_cbc();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_cbc();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_cbc();
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* Solitary case (when no full 16-byte block is present) */
    if (no_blocks == 0) {
       /*
        * scramble the solitary bytes XOR-ing them
        * with the most significant bytes of IV
        */
        for (i = 0; i < no_residuals; i++) {
            out[i] = in[i] ^ c->IV[i];
        }
    }
    else { /* Normal case where there are at least full blocks */
        /* create and initialize the context */
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            GST_ERROR_OBJECT (c, "failed to create context");
            return -1;
        }

        /* initialize the EVP context for AES CBC encryption */
        if (!EVP_EncryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV)) {
            GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
            goto err;
        }

        /* encrypt the full blocks */
        if (!EVP_EncryptUpdate(ctx, out, &out_len, in, no_blocks)) {
            GST_ERROR_OBJECT (c, "EVP_EncryptUpdate failed");
            goto err;
        }

        if (no_residuals != 0) {  /* residual case */
            /* pad the last partial block */
            memcpy(last_block, (in + no_blocks), no_residuals);

            /* encrypt the padded last block */
            if (!EVP_EncryptUpdate(ctx, temp, &out_len, last_block, 16)) {
                GST_ERROR_OBJECT (c, "EVP_EncryptUpdate failed");
                goto err;
            }

            /* cut the block before the last one and
             * swap it with the last one */
            memcpy(&(out[no_blocks]), &(out[no_blocks - 16]), no_residuals);
            memcpy(&(out[no_blocks - 16]), temp, 16);
        }

        /* finalize encryption (handles padding for the final block) */
        if (!EVP_EncryptFinal_ex(ctx, out + out_len, &final_len)) {
            GST_ERROR_OBJECT (c, "EVP_EncryptFinal_ex failed");
            goto err;
        }

        out_len += final_len;
        g_assert(out_len == len);

        /* clean up */
        EVP_CIPHER_CTX_free(ctx);
    }

    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_cbc_cs_decrypt(MpegTSCryptoCipher *c, uint8_t *in,
			int len, uint8_t *out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    uint8_t last_block[16] = {0};
    uint8_t residual[16] = {0};
    uint8_t temp[16] = {0};
    int i;
    int out_len = 0, final_len = 0;
    int no_residuals = len % 16;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 16) {
        cipher = EVP_aes_128_cbc();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_cbc();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_cbc();
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* solitary case (when no full 16-byte block is present) */
    if (no_blocks == 0) {
        /* scramble the solitary bytes XOR-ing them
           with the most significant bytes of IV */
        for (i = 0; i < no_residuals; i++) {
            out[i] = in[i] ^ c->IV[i];
        }
    }
    else {
        /* create and initialize the context */
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            GST_ERROR_OBJECT (c, "failed to create context");
            return -1;
        }

        /* initialize the EVP context for AES CBC decryption */
        if (!EVP_DecryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV)) {
            GST_ERROR_OBJECT (c, "EVP_DecryptInit_ex failed");
            return -1;
        }

        /* decrypt full blocks */
        if (no_residuals == 0) {  /* no residual case */
            if (!EVP_DecryptUpdate(ctx, out, &out_len, in, no_blocks)) {
                GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
                goto err;
            }
        }
        else {  /* residual case */
            /* decrypt up to the last full block */
            if (!EVP_DecryptUpdate(ctx, out, &out_len, in, no_blocks - 16)) {
                GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
                goto err;
            }

            /* handle residual block */
            memcpy(residual, (in + no_blocks), no_residuals);
            if (!EVP_DecryptUpdate(ctx, last_block, &out_len, &(in[no_blocks - 16]), 16)) {
                GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
                goto err;
            }

            /* merge residual with decrypted last block */
            memcpy(residual + no_residuals, last_block + no_residuals, 16 - no_residuals);
            if (!EVP_DecryptUpdate(ctx, temp, &out_len, residual, 16)) {
                GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
                goto err;
            }

            /* copy the decrypted residual part in the last block of 'out' */
            memcpy(out + no_blocks - 16, temp, 16);
            /* copy the 'last_block' array at the end of 'out' */
            memcpy(out + no_blocks, last_block, no_residuals);
        }

        /* terminate the stream */
        if (!EVP_DecryptFinal_ex(ctx, out + out_len, &final_len)) {
            GST_ERROR_OBJECT (c, "EVP_DecryptFinal_ex failed");
            goto err;
        }

        out_len += final_len;
        g_assert(out_len == len);

        EVP_CIPHER_CTX_free(ctx);
    }

    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_cbc_rsb_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
		uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len = 0, final_out_len = 0;
    int no_residuals = len % 16;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 16) {
        cipher = EVP_aes_128_cbc();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_cbc();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_cbc();
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        GST_ERROR_OBJECT (c, "failed to create context");
        return -1;
    }

    /* initialize AES-CBC encryption with the provided key and IV */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
        goto err;
    }

    /* encrypt the blocks */
    if (EVP_EncryptUpdate(ctx, out, &out_len, in, no_blocks) != 1) {
        GST_ERROR_OBJECT (c, " EVP_EncryptUpdate failed");
        goto err;
    }

    /* handle solitary or residual data (if any) by copying it as-is */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    /* finalize encryption */
    if (EVP_EncryptFinal_ex(ctx, out + out_len + no_residuals, &final_out_len) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptFinal_ex failed");
        goto err;
    }

    /* clean up and return */
    EVP_CIPHER_CTX_free(ctx);
    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_cbc_rsb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
			int len, uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len = 0, final_out_len = 0;
    int no_residuals = len % 16;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 16) {
        cipher = EVP_aes_128_cbc();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_cbc();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_cbc();
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        GST_ERROR_OBJECT (c, "failed to create context");
        return -1;
    }

    /* initialize AES-CBC decryption with the provided key and IV */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptInit_ex failed");
        goto err;
    }

    /* decrypt the blocks */
    if (EVP_DecryptUpdate(ctx, out, &out_len, in, no_blocks) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
        goto err;
    }

    /* handle residual data (if any) by copying it as-is */
    memcpy(out + out_len, in + no_blocks, no_residuals);

    /* finalize decryption */
    if (EVP_DecryptFinal_ex(ctx, out + out_len + no_residuals, &final_out_len) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptFinal_ex failed");
        goto err;
    }

    /* clean up and return */
    EVP_CIPHER_CTX_free(ctx);
    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static int _aes_cbc_scte_rs(uint8_t *in,
                              uint8_t *out,
                              uint8_t *rs,
                              int len,
                              uint8_t *k,
                              int key_size)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t tmp[key_size];
    int i, out_len = 0;

    /* clear the temporary buffer */
    memset(tmp, 0, key_size);

    /* initialize AES-ECB encryption context */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, k, NULL) != 1) {
        //GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* disable padding in ECB mode */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* encrypt the input data */
    if (EVP_EncryptUpdate(ctx, tmp, &out_len, in, key_size) != 1) {
        //GST_ERROR_OBJECT (c, "EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* perform XOR between the encrypted data and the scrambled input */
    for (i = 0; i < len; i++) {
        out[i] = tmp[i] ^ rs[i];
    }

    /* clean up and return */
    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes_cbc_scte_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
					uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len = 0;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 16) {
        cipher = EVP_aes_128_cbc();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_cbc();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_cbc();
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* handle solitary case (no blocks to encrypt) */
    if (no_blocks == 0) {
        if (_aes_cbc_scte_rs(c->IV, out, in, no_residuals,
                c->KEY, key_size) != no_residuals) {
            GST_ERROR_OBJECT (c, "CBC solitary case failed");
            return -1;
        }
    } else {
        /* create and initialize the context */
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            GST_ERROR_OBJECT (c, "failed to create context");
            return -1;
        }

        /* initialize AES-CBC encryption */
        if (EVP_EncryptInit_ex(ctx, cipher,
                    NULL, c->KEY, c->IV) != 1) {
            GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
            goto err;
        }

        /* encrypt the blocks */
        if (EVP_EncryptUpdate(ctx, out, &out_len, in, no_blocks) != 1) {
            GST_ERROR_OBJECT (c, "EVP_EncryptUpdate failed");
            goto err;
        }

        /* handle residual case */
        if (no_residuals != 0) {
            if (_aes_cbc_scte_rs(out + no_blocks - key_size,
                    out + no_blocks, in + no_blocks, no_residuals,
                    c->KEY, key_size) != no_residuals) {
                GST_ERROR_OBJECT (c, "CBC residual case failed");
                goto err;
            }
        }

        /* Finalize encryption */
        if (EVP_EncryptFinal_ex(ctx, out + out_len, &out_len) != 1) {
            GST_ERROR_OBJECT (c, "EVP_EncryptFinal_ex failed");
            goto err;
        }

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);
    }

    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_cbc_scte_decrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
			uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len = 0;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 16) {
        cipher = EVP_aes_128_cbc();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_cbc();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_cbc();
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* handle solitary case (no blocks to decrypt) */
    if (no_blocks == 0) {
        if (_aes_cbc_scte_rs(c->IV, out, in,
                no_residuals, c->KEY, key_size) != no_residuals) {
            GST_ERROR_OBJECT (c, "CBC solitary case failed");
            return -1;
        }
    } else {
        /* create and initialize the context */
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            GST_ERROR_OBJECT (c, "failed to create context");
            return -1;
        }

        /* initialize AES-CBC decryption */
        if (EVP_DecryptInit_ex(ctx, cipher,
                NULL, c->KEY, c->IV) != 1) {
            GST_ERROR_OBJECT (c, "EVP_DecryptInit_ex failed");
            goto err;
        }

        /* decrypt the blocks */
        if (EVP_DecryptUpdate(ctx, out, &out_len, in, no_blocks) != 1) {
            GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
            goto err;
        }

        /* handle residual case */
        if (no_residuals != 0) {
            if (_aes_cbc_scte_rs(in + no_blocks - key_size,
                    out + no_blocks, in + no_blocks, no_residuals,
                    c->KEY, key_size) != no_residuals) {
                GST_ERROR_OBJECT (c, " CBC residual case failed");
                goto err;
            }
        }

        /* finalize decryption */
        if (EVP_DecryptFinal_ex(ctx, out + out_len, &out_len) != 1) {
            GST_ERROR_OBJECT (c, "EVP_DecryptFinal_ex failed");
            goto err;
        }

        /* clean up */
        EVP_CIPHER_CTX_free(ctx);
    }

    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static int aes_ctr_encrypt(MpegTSCryptoCipher *c, uint8_t *in,
		int len, uint8_t *out, int key_size, int ctrlen)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int clen = 0, flen = 0, rlen = c->rbytes;
    int dlen = len;

    /* sanity check on input */
    if ((c->rbytes + dlen) < key_size) {
        GST_ERROR_OBJECT (c, "not enough data to be encrypted!");
        return -1;
    }

    if (key_size == 16) {
        cipher = EVP_aes_128_ctr();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_ctr();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_ctr();
    } else {
        GST_ERROR_OBJECT (c, "unsupported key size: %d", key_size);
        return -1;
    }

    /* adjust IV to have a 64-bit counter and zero out the upper 64 bits */
    if (ctrlen == 8)
        memset(&c->IV[8], 0, 8);

    /* create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        GST_ERROR_OBJECT (c, "EVP_CIPHER_CTX_new failed");
        return -1;
    }

    /* initialize the AES CTR mode with the appropriate key and IV */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
        goto err;
    }

    /* handle remaining bytes (if any) */
    if (rlen != 0) {
        dlen = rlen;
        GST_LOG_OBJECT (c, "%3d bytes (previous remainder)", dlen);
    } else {
        GST_LOG_OBJECT (c, "%3d bytes (current data)", dlen);
    }

    /* encrypt the data */
    if (EVP_EncryptUpdate(ctx, out, &clen, in, dlen) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptUpdate failed");
        goto err;
    }

    if (EVP_EncryptFinal_ex(ctx, out + clen, &flen) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptFinal_ex failed");
        goto err;
    }

    clen += flen;

    g_assert(clen != len);

    /* If we are not aligned on block size,
        save remaining bytes for the next call */
    if (EVP_CIPHER_CTX_block_size(ctx) != 0) {
        c->rbytes = EVP_CIPHER_CTX_block_size(ctx) - clen;
        GST_LOG_OBJECT (c, "remaining bytes: %d", c->rbytes);
    }

    /* save the current IV */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* For OpenSSL < 3.0, use the deprecated API */
    memcpy(c->IV, EVP_CIPHER_CTX_iv(ctx), sizeof(c->IV));
#endif

    /* clean up and return */
    EVP_CIPHER_CTX_free(ctx);
    return clen;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static int aes_ctr_decrypt(MpegTSCryptoCipher *c, uint8_t *in,
		int len, uint8_t *out, int key_size, int ctrlen)
{
    EVP_CIPHER_CTX *ctx;
    int clen = 0, flen = 0, rlen = c->rbytes;
    int dlen = len;
    const EVP_CIPHER *cipher = NULL;

    /* sanity check on input */
    if ((c->rbytes + dlen) < key_size) {
        GST_ERROR_OBJECT (c, "not enough data to be encrypted!");
        return -1;
    }

    if (key_size == 16) {
        cipher = EVP_aes_128_ctr();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_ctr();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_ctr();
    } else {
        GST_ERROR_OBJECT (c, "unsupported key size: %d", key_size);
        return -1;
    }

    /* adjust IV to have a 64-bit counter and zero out the upper 64 bits */
    if (ctrlen == 8)
        memset(&c->IV[8], 0, 8);

    /* create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        GST_ERROR_OBJECT (c, "failed to create context");
        return -1;
    }

    /* initialize the AES CTR mode with the appropriate key and IV */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
        goto err;
    }

    /* handle remaining bytes (if any) */
    if (rlen != 0) {
        dlen = rlen;
        GST_LOG_OBJECT (c, "%3d bytes (previous remainder)", dlen);
    } else {
        GST_LOG_OBJECT (c, "%3d bytes (current data)", dlen);
    }

    /* decrypt the data */
    if (EVP_DecryptUpdate(ctx, out, &clen, in, dlen) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
        goto err;
    }

    if (EVP_DecryptFinal_ex(ctx, out + clen, &flen) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptFinal_ex failed");
        goto err;
    }

    clen += flen;
    g_assert(clen != len);

    /* if we are not aligned on block size,
        save remaining bytes for the next call */
    if (EVP_CIPHER_CTX_block_size(ctx) != 0) {
        c->rbytes = EVP_CIPHER_CTX_block_size(ctx) - clen;
        GST_LOG_OBJECT (c, "remaining bytes: %d", c->rbytes);
    }

    /* save the current IV */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* For OpenSSL < 3.0, use the deprecated API */
    memcpy(c->IV, EVP_CIPHER_CTX_iv(ctx), sizeof(c->IV));
#endif

    /* clean up and return */
    EVP_CIPHER_CTX_free(ctx);
    return clen;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_ctr128_encrypt(MpegTSCryptoCipher *c, uint8_t *in,
		int len, uint8_t *out, int key_size)
{
    return aes_ctr_encrypt(c, in, len, out, key_size, 16);
}

int aes_ctr64_encrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
		uint8_t *out, int key_size)
{
    return aes_ctr_encrypt(c, in, len, out, key_size, 8);
}

int aes_ctr128_decrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
		uint8_t *out, int key_size)
{
    return aes_ctr_decrypt(c, in, len, out, key_size, 16);
}

int aes_ctr64_decrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
		uint8_t *out, int key_size)
{
    return aes_ctr_decrypt(c, in, len, out, key_size, 8);
}


int aes_ecb_encrypt(MpegTSCryptoCipher *c, uint8_t* in,
		int len, uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len1, out_len2;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* select the appropriate AES cipher based on the key size */
    if (key_size == 16) {
        cipher = EVP_aes_128_ecb();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_ecb();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_ecb();
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        GST_ERROR_OBJECT (c, "failed to create context");
        return -1;
    }

    /* initialize the context for encryption */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, c->KEY, NULL) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
        goto err;
    }

    /* disable padding (as ECB mode can 
        handle exact block sizes without padding) */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* encrypt the data block by block */
    if (EVP_EncryptUpdate(ctx, out, &out_len1, in, no_blocks) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptUpdate failed");
        goto err;
    }

    /* finalize encryption (required for block cipher modes) */
    if (EVP_EncryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptFinal_ex failed");
        goto err;
    }

    /* in case of residuals (data less than block size),
        copy remaining data as is */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    /* clean up */
    EVP_CIPHER_CTX_free(ctx);
    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_ecb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
		int len, uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len1, out_len2;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* Select the appropriate AES cipher based on the key size */
    if (key_size == 16) {
        cipher = EVP_aes_128_ecb();
    } else if (key_size == 24) {
        cipher = EVP_aes_192_ecb();
    } else if (key_size == 32) {
        cipher = EVP_aes_256_ecb();
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        GST_ERROR_OBJECT (c, "failed to create context");
        return -1;
    }

    /* initialize the context for decryption */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, c->KEY, NULL) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptInit_ex failed");
        goto err;
    }

    /* disable padding (as ECB mode can handle
            exact block sizes without padding) */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* decrypt the data block by block */
    if (EVP_DecryptUpdate(ctx, out, &out_len1, in, no_blocks) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
        goto err;
    }

    /* finalize decryption (required for block cipher modes) */
    if (EVP_DecryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptFinal_ex failed");
        goto err;
    }

    /* in case of residuals (data less than block size),
        copy remaining data as is */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    /* clean up */
    EVP_CIPHER_CTX_free(ctx);
    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}


int des_cbc_rsb_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
			uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len1, out_len2;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 8) {
        cipher = EVP_des_cbc();
    } else if (key_size == 16) {
        cipher = EVP_des_ede_cbc();  /* Triple DES (2-key) */
    } else if (key_size == 24) {
        cipher = EVP_des_ede3_cbc(); /* Triple DES (3-key) */
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        GST_ERROR_OBJECT (c, "failed to create context");
        return -1;
    }

    /* initialize the context for encryption */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
        goto err;
    }

    /* disable padding (to align with manual block size handling) */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* encrypt the data block by block */
    if (EVP_EncryptUpdate(ctx, out, &out_len1, in, no_blocks) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptUpdate failed");
        goto err;
    }

    /* finalize encryption (required for block ciphers) */
    if (EVP_EncryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptFinal_ex failed");
        goto err;
    }

    /* In case of residuals (data not fitting in the block size),
        copy remaining data as is */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    /* clean up */
    EVP_CIPHER_CTX_free(ctx);
    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int des_cbc_rsb_decrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
		uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len1, out_len2;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 8) {
        cipher = EVP_des_cbc();
    } else if (key_size == 16) {
        cipher = EVP_des_ede_cbc();  /* Triple DES (2-key) */
    } else if (key_size == 24) {
        cipher = EVP_des_ede3_cbc(); /* Triple DES (3-key) */
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        GST_ERROR_OBJECT (c, "failed to create context");
        return -1;
    }

    /* initialize the context for decryption */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptInit_ex failed");
        goto err;
    }

    /* disable padding (since you are handling the block size manually) */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* decrypt the data block by block */
    if (EVP_DecryptUpdate(ctx, out, &out_len1, in, no_blocks) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
        goto err;
    }

    /* finalize decryption (required for block ciphers) */
    if (EVP_DecryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptFinal_ex failed");
        goto err;
    }

    /* in case of residuals, copy the remaining data as is */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    /* clean up */
    EVP_CIPHER_CTX_free(ctx);
    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int tdes_cbc_rsb_encrypt(MpegTSCryptoCipher *c, uint8_t* in,
		int len, uint8_t* out, int key_size)
{
    return des_cbc_rsb_encrypt(c, in, len, out, key_size);
}

int tdes_cbc_rsb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
		int len, uint8_t* out, int key_size)
{
    return des_cbc_rsb_decrypt(c, in, len, out, key_size);
}

// Helper function for handling residual bytes using ECB mode and XOR
static int _des_cbc_scte_rs(uint8_t *in,
                              uint8_t *out,
                              uint8_t *rs,
                              int len,
                              uint8_t *k,
                              int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len1;
    uint8_t tmp[key_size];

    /* Select the appropriate DES cipher based on the key size */
    if (key_size == 8) {
        cipher = EVP_des_ecb();
    } else if (key_size == 16) {
        cipher = EVP_des_ede_ecb();  /* triple DES (2-key) */
    } else if (key_size == 24) {
        cipher = EVP_des_ede3_ecb(); /* triple DES (3-key) */
    } else {
        GST_ERROR ("invalid key size: %d", key_size);
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();

    /* initialize the context for ECB mode */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, k, NULL) != 1) {
        GST_ERROR ("EVP_EncryptInit_ex failed");
        goto err;
    }

    /* Disable padding since we're manually handling block sizes */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* perform ECB encryption */
    if (EVP_EncryptUpdate(ctx, tmp, &out_len1, in, key_size) != 1) {
        GST_ERROR ("EVP_EncryptUpdate failed");
        goto err;
    }

    /* XOR the encrypted data with the scrambled vector */
    for (int i = 0; i < len; i++) {
        out[i] = tmp[i] ^ rs[i];
    }

    /* clean up */
    EVP_CIPHER_CTX_free(ctx);

    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}


int des_cbc_scte_encrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
		uint8_t *out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len1, out_len2;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES CBC cipher based on the key size */
    if (key_size == 8) {
        cipher = EVP_des_cbc();
    } else if (key_size == 16) {
        cipher = EVP_des_ede_cbc();  /* triple DES (2-key) */
    } else if (key_size == 24) {
        cipher = EVP_des_ede3_cbc(); /* Triple DES (3-key) */
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* handle solitary case (no blocks, only residuals) */
    if (no_blocks == 0) {
        if (_des_cbc_scte_rs(c->IV, out, in, no_residuals,
                c->KEY, key_size) != no_residuals) {
            GST_ERROR_OBJECT (c, "%s: _des_cbc_scte_rs failed", __func__);
            return -1;
        }
    } else {
        ctx = EVP_CIPHER_CTX_new();

        /* initialize the context for CBC mode */
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
            GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
            goto err;
        }

        /* disable padding */
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        /* encrypt the blocks */
        if (EVP_EncryptUpdate(ctx, out, &out_len1, in, no_blocks) != 1) {
            GST_ERROR_OBJECT (c, "EVP_EncryptUpdate failed");
            goto err;
        }

        /* handle residuals */
        if (no_residuals != 0) {
            if (_des_cbc_scte_rs(out + no_blocks - key_size,
                    out + no_blocks, in + no_blocks, no_residuals,
                    c->KEY, key_size) != no_residuals) {
                GST_ERROR_OBJECT (c, "_des_cbc_scte_rs failed");
                goto err;
            }
        }

        /* finalize the encryption */
        if (EVP_EncryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
            GST_ERROR_OBJECT (c, "EVP_EncryptFinal_ex failed");
            goto err;
        }

        EVP_CIPHER_CTX_free(ctx);
    }

    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int des_cbc_scte_decrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
		uint8_t *out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len1, out_len2;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* Select the appropriate DES CBC cipher based on the key size */
    if (key_size == 8) {
        cipher = EVP_des_cbc();
    } else if (key_size == 16) {
        cipher = EVP_des_ede_cbc();  /* triple DES (2-key) */
    } else if (key_size == 24) {
        cipher = EVP_des_ede3_cbc(); /* triple DES (3-key) */
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* handle solitary case (no blocks, only residuals) */
    if (no_blocks == 0) {
        if (_des_cbc_scte_rs(c->IV, out, in, no_residuals,
                c->KEY, key_size) != no_residuals) {
            GST_ERROR_OBJECT (c, "_des_cbc_scte_rs failed");
            return -1;
        }
    } else {
        ctx = EVP_CIPHER_CTX_new();

        /* initialize the context for CBC mode */
        if (EVP_DecryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
            GST_ERROR_OBJECT (c, "EVP_DecryptInit_ex failed");
            goto err;
        }

        /* disable padding */
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        /* decrypt the blocks */
        if (EVP_DecryptUpdate(ctx, out, &out_len1, in, no_blocks) != 1) {
            GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
            goto err;
        }

        /* handle residuals */
        if (no_residuals != 0) {
            if (_des_cbc_scte_rs(in + no_blocks - key_size,
                    out + no_blocks, in + no_blocks, no_residuals,
                    c->KEY, key_size) != no_residuals) {
                GST_ERROR_OBJECT (c, "des_cbc_scte_rs failed");
                goto err;
            }
        }

        /* finalize the decryption */
        if (EVP_DecryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
            GST_ERROR_OBJECT (c, "EVP_DecryptFinal_ex failed");
            goto err;
        }

        EVP_CIPHER_CTX_free(ctx);
    }

    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int tdes_cbc_scte_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
				uint8_t* out, int key_size)
{
    return des_cbc_scte_encrypt(c, in, len, out, key_size);
}

int tdes_cbc_scte_decrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
		uint8_t* out, int key_size)
{
    return des_cbc_scte_decrypt(c, in, len, out, key_size);
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
int des_ecb_encrypt(MpegTSCryptoCipher *c, uint8_t* in,
		int len, uint8_t* out, int key_size)
{
    DES_key_schedule ks;
    DES_cblock key;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;
    
    /* set up the key */
    memcpy(key, c->KEY, key_size);
    DES_set_key_unchecked(&key, &ks);

    /* encrypt the blocks */
    for (int i = 0; i < no_blocks; i += key_size) {
        DES_ecb_encrypt((DES_cblock*)(in + i),
            (DES_cblock*)(out + i), &ks, DES_ENCRYPT);
    }

    /* in case of solitary or residuals, copy remaining data from in to out */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    return len;
}

int des_ecb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
		int len, uint8_t* out, int key_size)
{
    DES_key_schedule ks;
    DES_cblock key;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* set up the key */
    memcpy(key, c->KEY, key_size);
    DES_set_key_unchecked(&key, &ks);

    /* decrypt the blocks */
    for (int i = 0; i < no_blocks; i += key_size) {
        DES_ecb_encrypt((DES_cblock*)(in + i),
            (DES_cblock*)(out + i), &ks, DES_DECRYPT);
    }

    /* in case of solitary or residuals, copy remaining data from in to out */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    return len;
}

int tdes_ecb_encrypt(MpegTSCryptoCipher *c, uint8_t* in,
		int len, uint8_t* out, int key_size)
{
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock key1, key2, key3;
    int no_residuals = len % 8;  /* DES block size is always 8 bytes */
    int no_blocks = len - no_residuals;

    /* check if key_size is large enough for 3DES (24 bytes) */
    if (key_size < 24) {
        GST_ERROR_OBJECT (c, "key_size too small for TDES");
        return -1;
    }

    /* set up the 3 keys for TDES */
    memcpy(key1, c->KEY, 8);
    memcpy(key2, c->KEY + 8, 8);
    memcpy(key3, c->KEY + 16, 8);

    DES_set_key_unchecked(&key1, &ks1);
    DES_set_key_unchecked(&key2, &ks2);
    DES_set_key_unchecked(&key3, &ks3);

    /* encrypt the blocks */
    for (int i = 0; i < no_blocks; i += 8) {
        DES_ecb3_encrypt((DES_cblock*)(in + i),
            (DES_cblock*)(out + i), &ks1, &ks2, &ks3, DES_ENCRYPT);
    }

    /* in case of solitary or residuals, copy remaining data from in to out */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    return len;
}

int tdes_ecb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
		int len, uint8_t* out, int key_size)
{
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock key1, key2, key3;
    int no_residuals = len % 8;  /* DES block size is always 8 bytes */
    int no_blocks = len - no_residuals;

    /* check if key_size is large enough for 3DES (24 bytes) */
    if (key_size < 24) {
        GST_ERROR_OBJECT (c, "key_size too small for TDES");
        return -1;
    }

    /* set up the 3 keys for TDES */
    memcpy(key1, c->KEY, 8);
    memcpy(key2, c->KEY + 8, 8);
    memcpy(key3, c->KEY + 16, 8);

    DES_set_key_unchecked(&key1, &ks1);
    DES_set_key_unchecked(&key2, &ks2);
    DES_set_key_unchecked(&key3, &ks3);

    /* decrypt the blocks */
    for (int i = 0; i < no_blocks; i += 8) {
        DES_ecb3_encrypt((DES_cblock*)(in + i),
            (DES_cblock*)(out + i), &ks1, &ks2, &ks3, DES_DECRYPT);
    }

    /* in case of solitary or residuals, copy remaining data from in to out */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    return len;
}
#else
int des_ecb_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
            uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len1, out_len2;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 8) {
        cipher = EVP_des_ecb();
    } else if (key_size == 16) {
        cipher = EVP_des_ede_ecb();  /* Triple DES (2-key) */
    } else if (key_size == 24) {
        cipher = EVP_des_ede3_ecb(); /* Triple DES (3-key) */
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        GST_ERROR_OBJECT (c, "failed to create context");
        return -1;
    }

    /* initialize the context for encryption */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptInit_ex failed");
        goto err;
    }

    /* disable padding (as ECB mode can 
        handle exact block sizes without padding) */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* perform the encryption */
    if (EVP_EncryptUpdate(ctx, out, &out_len1, in, len) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptUpdate failed");
        goto err;
    }

    /* finalize encryption (not needed for ECB, but required by the API) */
    if (EVP_EncryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
        GST_ERROR_OBJECT (c, "EVP_EncryptFinal_ex failed");
        goto err;
    }

    /* in case of residuals (data less than block size),
        copy remaining data as is */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    /* clean up */
    EVP_CIPHER_CTX_free(ctx);
    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int des_ecb_decrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
            uint8_t* out, int key_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int out_len1, out_len2;
    int no_residuals = len % key_size;
    int no_blocks = len - no_residuals;

    /* select the appropriate DES cipher based on the key size */
    if (key_size == 8) {
        cipher = EVP_des_ecb();
    } else if (key_size == 16) {
        cipher = EVP_des_ede_ecb();  /* Triple DES (2-key) */
    } else if (key_size == 24) {
        cipher = EVP_des_ede3_ecb(); /* Triple DES (3-key) */
    } else {
        GST_ERROR_OBJECT (c, "invalid key size: %d", key_size);
        return -1;
    }

    /* create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        GST_ERROR_OBJECT (c, "failed to create context");
        return -1;
    }

    /* initialize the context for encryption */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, c->KEY, c->IV) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptInit_ex failed");
        goto err;
    }

    /* disable padding (as ECB mode can 
        handle exact block sizes without padding) */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* perform the encryption */
    if (EVP_DecryptUpdate(ctx, out, &out_len1, in, len) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptUpdate failed");
        goto err;
    }

    /* finalize encryption (not needed for ECB, but required by the API) */
    if (EVP_DecryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
        GST_ERROR_OBJECT (c, "EVP_DecryptFinal_ex failed");
        goto err;
    }

    /* in case of residuals (data less than block size),
        copy remaining data as is */
    memcpy(out + no_blocks, in + no_blocks, no_residuals);

    /* clean up */
    EVP_CIPHER_CTX_free(ctx);
    return len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int tdes_ecb_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
                uint8_t* out, int key_size)
{
    return des_ecb_encrypt(c, in, len, out, key_size);
}

int tdes_ecb_decrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
        uint8_t* out, int key_size)
{
    return des_ecb_decrypt(c, in, len, out, key_size);
}
#endif

#ifdef HAVE_LIBDVBCSA
int dvb_csa_encrypt(MpegTSCryptoCipher *c, uint8_t *in,
		int len, uint8_t *out, int key_size)
{
#ifndef CSA_DISABLE
    /* allocate dvb csa key */
    struct dvbcsa_key_s *csa_key = dvbcsa_key_alloc();

    /* set the key */
    dvbcsa_key_set(c->KEY, csa_key);

    /* clear the output buffer (optional, for safety) */
    memset(out, 0, len);

    /* copy input directly to output buffer before encryption */
    memcpy(out, in, len);

    /* encrypt the data */
    dvbcsa_encrypt(csa_key, out, len);

    /* free the key */
    dvbcsa_key_free(csa_key);

    return len;
#else
    return 0;
#endif
}

int dvb_csa_decrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
		uint8_t *out, int key_size)
{
#ifndef CSA_DISABLE
    /* allocate dvb csa key */
    struct dvbcsa_key_s *csa_key = dvbcsa_key_alloc();

    /* set the key */
    dvbcsa_key_set(c->KEY, csa_key);

    /* clear the output buffer (optional, for safety) */
    memset(out, 0, len);

    /* copy input directly to output buffer before decryption */
    memcpy(out, in, len);

    /* decrypt the data */
    dvbcsa_decrypt(csa_key, out, len);

    /* free the key */
    dvbcsa_key_free(csa_key);

    return len;
#else
    return 0;
#endif
}

#ifndef CSA3_DISABLE

#define CSA3_CW_SIZE 16
#define byte uint8_t
extern void CSA3_encrypt(byte ct[], const byte pt[], int len,
             const byte cw[CSA3_CW_SIZE]);
extern void CSA3_decrypt(byte pt[], const byte ct[], int len,
             const byte cw[CSA3_CW_SIZE]);

int dvb_csa3_encrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
			uint8_t *out, int key_size) {
    CSA3_encrypt(out, in, len, c->KEY);
    return len;
}

int dvb_csa3_decrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
		uint8_t *out, int key_size) {
    CSA3_decrypt(out, in, len, c->KEY);
    return len;
}
#endif

#endif