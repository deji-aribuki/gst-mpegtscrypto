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

#ifndef GST_MPEGTSCRYPTO_CIPHER_H
#define GST_MPEGTSCRYPTO_CIPHER_H

#include <gst/gst.h>
#include <gst/base/gstadapter.h>
#include <glib.h>


G_BEGIN_DECLS

#define GST_TYPE_MPEGTSCRYPTO_CIPHER \
  (mpegts_cipher_get_type())
#define GST_MPEGTSCRYPTO_CIPHER(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_MPEGTSCRYPTO_CIPHER,MpegTSCryptoCipher))
#define GST_MPEGTSCRYPTO_CIPHER_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_MPEGTSCRYPTO_CIPHER,MpegTSCryptoCipherClass))
#define GST_IS_MPEGTSCRYPTO_CIPHER(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_MPEGTSCRYPTO_CIPHER))
#define GST_IS_MPEGTSCRYPTO_CIPHER_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_MPEGTSCRYPTO_CIPHER))

typedef struct _MpegTSCryptoCipher MpegTSCryptoCipher;
typedef struct _MpegTSCryptoCipherClass MpegTSCryptoCipherClass;



/* define PID parameters */
struct _MpegTSCryptoCipher {
   /**/
   int key_size;
   /* current selected key, iv */
   uint8_t *KEY, *IV;
   /* remaining bytes len */
   uint8_t rbytes;
};


G_GNUC_INTERNAL GType mpegtscrypto_cipher_get_type(void);

int aes_cbc_cs_encrypt(MpegTSCryptoCipher *c, uint8_t *in,
      int len, uint8_t *out, int key_size);
int aes_cbc_cs_decrypt(MpegTSCryptoCipher *c, uint8_t *in,
         int len, uint8_t *out, int key_size);
int aes_cbc_rsb_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
      uint8_t* out, int key_size);
int aes_cbc_rsb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
         int len, uint8_t* out, int key_size);
int aes_cbc_rsb_encrypt(MpegTSCryptoCipher *c, uint8_t* in,
         int len, uint8_t* out, int key_size);
int aes_cbc_rsb_decrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
         uint8_t* out, int key_size);
int aes_cbc_scte_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
               uint8_t* out, int key_size);
int aes_cbc_scte_decrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
         uint8_t* out, int key_size);
int aes_ctr64_encrypt(MpegTSCryptoCipher *c, uint8_t *in,
      int len, uint8_t *out, int key_size);
int aes_ctr64_decrypt(MpegTSCryptoCipher *c, uint8_t *in,
      int len, uint8_t *out, int key_size);
int aes_ctr128_encrypt(MpegTSCryptoCipher *c, uint8_t *in,
      int len, uint8_t *out, int key_size);
int aes_ctr128_decrypt(MpegTSCryptoCipher *c, uint8_t *in,
      int len, uint8_t *out, int key_size);
int aes_ecb_encrypt(MpegTSCryptoCipher *c, uint8_t* in,
      int len, uint8_t* out, int key_size);
int aes_ecb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
      int len, uint8_t* out, int key_size);
int des_cbc_rsb_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
         uint8_t* out, int key_size);
int des_cbc_rsb_decrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
      uint8_t* out, int key_size);
int tdes_cbc_rsb_encrypt(MpegTSCryptoCipher *c, uint8_t* in,
      int len, uint8_t* out, int key_size);
int tdes_cbc_rsb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
      int len, uint8_t* out, int key_size);
int des_cbc_scte_encrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
      uint8_t *out, int key_size);
int des_cbc_scte_decrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
      uint8_t *out, int key_size);
int tdes_cbc_scte_encrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
            uint8_t* out, int key_size);
int tdes_cbc_scte_decrypt(MpegTSCryptoCipher *c, uint8_t* in, int len,
      uint8_t* out, int key_size);
int des_ecb_encrypt(MpegTSCryptoCipher *c, uint8_t* in,
      int len, uint8_t* out, int key_size);
int des_ecb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
      int len, uint8_t* out, int key_size);
int tdes_ecb_encrypt(MpegTSCryptoCipher *c, uint8_t* in,
      int len, uint8_t* out, int key_size);
int tdes_ecb_decrypt(MpegTSCryptoCipher *c, uint8_t* in,
      int len, uint8_t* out, int key_size);
int dvb_csa_encrypt(MpegTSCryptoCipher *c, uint8_t *in,
      int len, uint8_t *out, int key_size);
int dvb_csa_decrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
      uint8_t *out, int key_size);
int dvb_csa3_encrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
         uint8_t *out, int key_size);
int dvb_csa3_decrypt(MpegTSCryptoCipher *c, uint8_t *in, int len,
      uint8_t *out, int key_size);


#endif /* GST_MPEGTSCRYPTO_CIPHER_H */