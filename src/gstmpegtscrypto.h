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

#ifndef GST_MPEGTSCRYPTO_H
#define GST_MPEGTSCRYPTO_H

#include <stdint.h>

#include <gst/gst.h>
#include <gst/base/gstbasetransform.h>
#include "gstmpegtspacketizer.h"
#include "gstmpegtscipher.h"

G_BEGIN_DECLS

#define GST_TYPE_MPEGTSCRYPTO \
  (mpegtscrypto_get_type())
#define GST_MPEGTSCRYPTO(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_MPEGTSCRYPTO,MpegTSCrypto))
#define GST_MPEGTSCRYPTO_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_MPEGTSCRYPTO,MpegTSCryptoClass))
#define GST_IS_MPEGTSCRYPTO(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_MPEGTSCRYPTO))
#define GST_IS_MPEGTSCRYPTO_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_MPEGTSCRYPTO))
#define GST_MPEGTSCRYPTO_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), GST_TYPE_MPEGTSCRYPTO, MpegTSCryptoClass))


typedef struct _MpegTSCrypto MpegTSCrypto;
typedef struct _MpegTSCryptoClass MpegTSCryptoClass;
typedef enum _MpegTSCryptoMode MpegTSCryptoMode;
typedef enum _MpegTSCryptoTSCFlag MpegTSCryptoTSCFlag;
typedef enum _MpegTSCryptoParity MpegTSCryptoParity;

enum _MpegTSCryptoMode {
    MPEGTSCRYPTO_MODE_ENCRYPT,
    MPEGTSCRYPTO_MODE_DECRYPT,
};

enum _MpegTSCryptoTSCFlag {
  MPEGTSCRYPTO_TSCFLAG_CLEAR,
  MPEGTSCRYPTO_TSCFLAG_AUTO,
  MPEGTSCRYPTO_TSCFLAG_EVEN,
  MPEGTSCRYPTO_TSCFLAG_ODD,
};

enum _MpegTSCryptoParity {
  MPEGTSCRYPTO_PARITY_AUTO,
  MPEGTSCRYPTO_PARITY_TSC,
  MPEGTSCRYPTO_PARITY_EVEN,
  MPEGTSCRYPTO_PARITY_ODD,
};


struct _MpegTSCrypto {
  GstBaseTransform element;

  GstPad *sinkpad;
  GstPad *srcpad;

  MpegTSPacketizer2 *packetizer;
  MpegTSCryptoCipher cipher;
  MpegTSCryptoMode mode;

  /* properties */
  gchar *algo;
  gchar *even_key;
  gchar *odd_key;
  gchar *even_iv;
  gchar *odd_iv;
  GArray *pids;
  MpegTSCryptoTSCFlag tsc_flag;
  MpegTSCryptoParity parity;
  gint16 packet_size;

   /* crypto key associated: even = 0, odd = 1 */
   uint8_t key[2][32];
   /* crypto iv associated */
   uint8_t iv[2][16];
   /**/
   int key_size;
   /**/
   int (*process) (MpegTSCryptoCipher *cipher, uint8_t *in, int len,
          uint8_t *out, int key_size);
};

struct _MpegTSCryptoClass {
  GstBaseTransformClass parent_class;

};

#define MPEGTS_BIT_SET(field, offs)    ((field)[(offs) >> 3] |=  (1 << ((offs) & 0x7)))
#define MPEGTS_BIT_UNSET(field, offs)  ((field)[(offs) >> 3] &= ~(1 << ((offs) & 0x7)))
#define MPEGTS_BIT_IS_SET(field, offs) ((field)[(offs) >> 3] &   (1 << ((offs) & 0x7)))

#define MPEGTS_FLAGS_SCRAMBLED(f) (f & 0xc0)
#define MPEGTS_FLAGS_HAS_AFC(f) (f & 0x20)
#define MPEGTS_FLAGS_HAS_PAYLOAD(f) (f & 0x10)
#define MPEGTS_FLAGS_CONTINUITY_COUNTER(f) (f & 0x0f)

#define MPEGTS_FLAGS_SCRAMBLED_ODD(f) (f & 0x40)
#define MPEGTS_FLAGS_SCRAMBLED_EVEN(f) ((f & 0x40) && (f & 0x80))

/* scr_ctrl flag values */
#define MPEGTS_SCR_CTRL_NO_SCR       0
#define MPEGTS_SCR_CTRL_RFU          1
#define MPEGTS_SCR_CTRL_PARITY_EVEN  2
#define MPEGTS_SCR_CTRL_PARITY_ODD   3

/* adaptation field control flag */
#define MPEGTS_AF_CTRL_NULL_PACKET      0
#define MPEGTS_AF_CTRL_PAYLOAD_ONLY     1
#define MPEGTS_AF_CTRL_AF_FIELD_ONLY    2
#define MPEGTS_AF_CTRL_AF_AND_PAYLOAD   3

G_GNUC_INTERNAL GType mpegtscrypto_get_type(void);

G_END_DECLS

#endif /* GST_MPEGTSCRYPTO_H */
