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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <gst/gst.h>
#include <gst/base/gstbasetransform.h>

#include "gstmpegtscrypto.h"
#include "gstmpegtspacketizer.h"
#include "gstmpegtscipher.h"

#define DEFAULT_KEY "1f9423681beb9a79215820f6bda73d0f"
#define DEFAULT_IV "00000000000000000000000000000000"
#define DEFAULT_PID 0x2000 /* process all packets */
#define DEFAULT_ALGO "aes-128-cbc-cs"
#define DEFAULT_PACKETSIZE 188

GST_DEBUG_CATEGORY_STATIC (mpegtscrypto_debug);
#define GST_CAT_DEFAULT mpegtscrypto_debug


enum
{
  LAST_SIGNAL
};

#define MPEGTSCRYPTO_TSCFLAG_TYPE (gst_mpegtscrypto_tscflag_get_type())
static GType
gst_mpegtscrypto_tscflag_get_type (void)
{
  static gsize g_type = 0;

  static const GEnumValue enum_values[] = {
    {MPEGTSCRYPTO_TSCFLAG_CLEAR, "Set TSC bits to clear", "clear"},
    {MPEGTSCRYPTO_TSCFLAG_AUTO, "Do not touch TSC bits", "auto"},
    {MPEGTSCRYPTO_TSCFLAG_EVEN, "Set TSC bits to even", "even"},
    {MPEGTSCRYPTO_TSCFLAG_ODD, "Set TSC bits to odd", "odd"},
    {0, NULL, NULL},
  };

  if (g_once_init_enter (&g_type)) {
    const GType type =
        g_enum_register_static ("GstMpegTSCryptoTSCFlag", enum_values);
    g_once_init_leave (&g_type, type);
  }
  return g_type;
}

#define MPEGTSCRYPTO_PARITY_TYPE (gst_mpegtscrypto_parity_get_type())
static GType
gst_mpegtscrypto_parity_get_type (void)
{
  static gsize g_type = 0;

  static const GEnumValue enum_values[] = {
    {MPEGTSCRYPTO_PARITY_AUTO, "Use key in crypto-period", "auto"},
    {MPEGTSCRYPTO_PARITY_TSC, "Follow TSC bits", "tsc"},
    {MPEGTSCRYPTO_PARITY_EVEN, "Use key even", "even"},
    {MPEGTSCRYPTO_PARITY_ODD, "Use key odd", "odd"},
    {0, NULL, NULL},
  };

  if (g_once_init_enter (&g_type)) {
    const GType type =
        g_enum_register_static ("GstMpegTSCryptoParity", enum_values);
    g_once_init_leave (&g_type, type);
  }
  return g_type;
}

enum
{
  PROP_0,
  PROP_PIDS,
  PROP_ALGO,
  PROP_ODD_KEY,
  PROP_EVEN_KEY,
  PROP_ODD_IV,
  PROP_EVEN_IV,
  PROP_PACKETSIZE,
  PROP_TSC_FLAG,
  PROP_PARITY,
  PROP_CRYPTO_PERIOD,
};

/* the capabilities of the inputs and outputs.
 *
 */
static GstStaticPadTemplate sink_template = GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/mpegts, "
        "systemstream = (boolean) true, " "packetsize = (int) { 188, 192} ")
    );

static GstStaticPadTemplate src_template = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/mpegts, "
        "systemstream = (boolean) true, " "packetsize = (int) { 188, 192} ")
    );

#define mpegtscrypto_parent_class parent_class
G_DEFINE_TYPE (MpegTSCrypto, mpegtscrypto, GST_TYPE_BASE_TRANSFORM);


//static void mpegtscrypto_dispose (GObject * object);
static void mpegtscrypto_finalize (GObject * object);
static void mpegtscrypto_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec);
static void mpegtscrypto_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec);

static GstFlowReturn mpegtscrypto_transform_ip (GstBaseTransform * base,
    GstBuffer * buf);
static gboolean mpegtscrypto_start (GstBaseTransform * base);
static gboolean mpegtscrypto_stop (GstBaseTransform * base);

static gboolean mpegtscrypto_encrypt (MpegTSCrypto *filter,
    MpegTSPacketizerPacket *pkt);
static gboolean mpegtscrypto_decrypt (MpegTSCrypto *filter,
    MpegTSPacketizerPacket *pkt);


typedef struct _MpegTSCryptoCipherParam {
   gchar *name;
   uint8_t key_size;
   uint8_t iv_size;
   int (*encrypt) (MpegTSCryptoCipher *c, uint8_t *in, int len, uint8_t *out,
         int key_size);
   int (*decrypt) (MpegTSCryptoCipher *c, uint8_t *in, int len, uint8_t *out,
         int key_size);
} MpegTSCryptoCipherParam;

MpegTSCryptoCipherParam cipher_list[] = {
   /* cipher , key_size, iv_size, encrypt funtion, decrypt function */
   { "aes-128-ecb", 16, 0, aes_ecb_encrypt, aes_ecb_decrypt },
   { "aes-128-cbc-rsb", 16, 16,  aes_cbc_rsb_encrypt, aes_cbc_rsb_decrypt },
   { "aes-128-cbc-scte", 16, 16, aes_cbc_scte_encrypt, aes_cbc_scte_decrypt },
   { "aes-128-cbc-cs", 16, 16, aes_cbc_cs_encrypt, aes_cbc_cs_decrypt },
   { "aes-128-ctr", 16, 16, aes_ctr128_encrypt, aes_ctr128_decrypt },
   { "aes-128-ctr64", 16, 16, aes_ctr64_encrypt, aes_ctr64_decrypt },
   { "aes-256-ecb", 32, 0, aes_ecb_encrypt, aes_ecb_decrypt },
   { "aes-256-cbc-rsb", 32, 16,  aes_cbc_rsb_encrypt, aes_cbc_rsb_decrypt },
   { "aes-256-cbc-scte", 32, 16, aes_cbc_scte_encrypt, aes_cbc_scte_decrypt },
   { "aes-256-cbc-cs", 32, 16, aes_cbc_cs_encrypt, aes_cbc_cs_decrypt },
   { "aes-256-ctr", 32, 16, aes_ctr128_encrypt, aes_ctr128_decrypt },
   { "aes-256-ctr64", 32, 16, aes_ctr64_encrypt, aes_ctr64_decrypt },
   { "des-ecb",  8, 0, des_ecb_encrypt, des_ecb_decrypt },
   { "des-cbc-rsb",  8, 8, des_cbc_rsb_encrypt, des_cbc_rsb_decrypt },
   { "des-cbc-scte",  8, 8, des_cbc_scte_encrypt, des_cbc_scte_decrypt },
   { "tdes-ecb",  24, 0, tdes_ecb_encrypt, tdes_ecb_decrypt },
   { "tdes-cbc-rsb",  24, 8, tdes_cbc_rsb_encrypt, tdes_cbc_rsb_decrypt },
   { "tdes-cbc-scte", 24, 8, tdes_cbc_scte_encrypt, tdes_cbc_scte_decrypt },
#ifdef HAVE_LIBDVBCSA
   { "dvb-csa", 8, 0, dvb_csa_encrypt, dvb_csa_decrypt },
#ifdef CSA3_ENABLE
   { "dvb-csa3", 16, 0, dvb_csa3_encrypt, dvb_csa3_decrypt },
#endif
#endif
   { NULL, 0, 0, NULL, NULL },
};


static void
mpegtscrypto_class_init (MpegTSCryptoClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *element_class;

  element_class = GST_ELEMENT_CLASS (klass);
  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = mpegtscrypto_finalize;
  gobject_class->set_property = mpegtscrypto_set_property;
  gobject_class->get_property = mpegtscrypto_get_property;

  g_object_class_install_property (gobject_class, PROP_PACKETSIZE,
      g_param_spec_uint("packet-size", "TS Packet Size",
          "Size of the TS packet (188 or 192)", 188, 192,
          DEFAULT_PACKETSIZE, G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_PIDS,
      g_param_spec_value_array ("pids", "PIDS",
          "List of PIDs to scramble/descramble (default all pids)",
          g_param_spec_uint ("pid", "PID",
              "pid", 0 /* min */, 0x2000 /* max */, DEFAULT_PID,
              G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS),
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_ODD_KEY,
      g_param_spec_string ("odd-key", "Odd Key",
          "Key used for odd packets", DEFAULT_KEY, G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_EVEN_KEY,
      g_param_spec_string ("even-key", "Even Key",
          "Key used for even packets", DEFAULT_KEY, G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_ODD_IV,
      g_param_spec_string ("odd-iv", "Odd IV",
          "IV used for odd packets", DEFAULT_IV, G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_EVEN_IV,
      g_param_spec_string ("even-iv", "Even IV",
          "IV used for even packets", DEFAULT_IV, G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_ALGO,
      g_param_spec_string("algo", "Crypto Algorithm",
          "Supported algorithms are "
          "aes-128-ecb, aes-128-cbc-rsb, aes-128-cbc-scte, "
          "aes-128-cbc-cs (default), aes-128-ctr, aes-128-ctr64, "
          "aes-256-ecb, aes-256-cbc-rsb, aes-256-cbc-scte, "
          "aes-256-cbc-cs, aes-256-ctr, aes-256-ctr64, "
          "des-ecb, des-cbc-rsb, des-cbc-scte, tdes-ecb, "
          "tdes-ecb-cs, tdes-cbc-rsb, tdes-cbc-scte, dvb-csa, dvb-csa3",
          DEFAULT_ALGO, G_PARAM_READWRITE));

  /* only for decrypt */
  g_object_class_install_property (gobject_class, PROP_TSC_FLAG,
          g_param_spec_enum ("tsc-flag", "TSC Flag", 
              "MPEG-TS packet TSC bits to be set by descrambler",
              MPEGTSCRYPTO_TSCFLAG_TYPE,
              MPEGTSCRYPTO_TSCFLAG_CLEAR,
              G_PARAM_READWRITE));

  /* only for encrypt */
  g_object_class_install_property (gobject_class, PROP_PARITY,
          g_param_spec_enum ("parity", "Parity", 
              "Encryption key to be used by scrambler",
              MPEGTSCRYPTO_PARITY_TYPE,
              MPEGTSCRYPTO_PARITY_EVEN,
              G_PARAM_READWRITE));

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&src_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&sink_template));

  gst_element_class_set_details_simple(element_class,
      "MPEG-TS Crypto",
      "Codec/Parser",
      "Crypto operation on MPEG-TS streams using AES/DES/TDES",
      "Deji Aribuki <deji.aribuki@ketulabs.com>, <deji.aribuki@gmail.com>");

  //klass->sink_query = GST_DEBUG_FUNCPTR (mpegtscrypto_default_sink_query);

  GST_BASE_TRANSFORM_CLASS (klass)->transform_ip =
      GST_DEBUG_FUNCPTR (mpegtscrypto_transform_ip);
  GST_BASE_TRANSFORM_CLASS (klass)->start =
      GST_DEBUG_FUNCPTR (mpegtscrypto_start);
  GST_BASE_TRANSFORM_CLASS (klass)->stop =
      GST_DEBUG_FUNCPTR (mpegtscrypto_stop);

  /* debug category for fltering log messages */
  GST_DEBUG_CATEGORY_INIT (mpegtscrypto_debug, "mpegtscrypto", 0,
      "Encrypt/decrypt mpegts");
}

static void
mpegtscrypto_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  MpegTSCrypto *filter = GST_MPEGTSCRYPTO (object);

  switch (prop_id) {
      case PROP_PACKETSIZE:
          filter->packet_size = g_value_get_uint (value);
          break;
      case PROP_PIDS:
          if (filter->pids)
              g_array_free (filter->pids, TRUE);
          filter->pids = g_value_dup_boxed (value);
          break;
      case PROP_ODD_KEY:
          g_free (filter->odd_key);
          filter->odd_key = g_value_dup_string (value);
          break;
      case PROP_EVEN_KEY:
          g_free (filter->even_key);
          filter->even_key = g_value_dup_string (value);
          break;
      case PROP_ODD_IV:
          g_free (filter->odd_iv);
          filter->odd_iv = g_value_dup_string (value);
          break;
      case PROP_EVEN_IV:
          g_free (filter->even_iv);
          filter->even_iv = g_value_dup_string (value);
          break;
      case PROP_ALGO:
          g_free (filter->algo);
          filter->algo = g_value_dup_string (value);
          break;
      case PROP_TSC_FLAG:
          filter->tsc_flag = (MpegTSCryptoTSCFlag) g_value_get_enum (value);
          break;
      case PROP_PARITY:
          filter->parity = (MpegTSCryptoParity) g_value_get_enum (value);
          break;
      default:
          G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
          break;
  }
}

static void
mpegtscrypto_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  MpegTSCrypto *filter = GST_MPEGTSCRYPTO (object);

  switch (prop_id) {
      case PROP_PACKETSIZE:
          g_value_set_uint (value, filter->packet_size);
          break;
      case PROP_PIDS:
          g_value_set_boxed (value, filter->pids);
          break;
      case PROP_ODD_KEY:
          g_value_set_string (value, filter->odd_key);
          break;
      case PROP_EVEN_KEY:
          g_value_set_string (value, filter->even_key);
          break;
      case PROP_ODD_IV:
          g_value_set_string (value, filter->odd_iv);
          break;
      case PROP_EVEN_IV:
          g_value_set_string (value, filter->even_iv);
          break;
      case PROP_ALGO:
          g_value_set_string (value, filter->algo);
          break;
      case PROP_TSC_FLAG:
          g_value_set_enum (value, filter->tsc_flag);
          break;
      case PROP_PARITY:
          g_value_set_enum (value, filter->parity);
          break;
      default:
          G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
          break;
  }
}

static void
mpegtscrypto_init (MpegTSCrypto * filter)
{
  filter->packetizer = mpegts_packetizer_new ();

  filter->algo = g_strdup (DEFAULT_ALGO);
  filter->even_key = g_strdup (DEFAULT_KEY);
  filter->odd_key = g_strdup (DEFAULT_KEY);
  filter->even_iv = g_strdup (DEFAULT_IV);
  filter->odd_iv = g_strdup (DEFAULT_IV);
  filter->pids = NULL;
  filter->packet_size = DEFAULT_PACKETSIZE;
  filter->mode = MPEGTSCRYPTO_MODE_ENCRYPT;
  filter->tsc_flag = MPEGTSCRYPTO_TSCFLAG_CLEAR;
  filter->parity = MPEGTSCRYPTO_PARITY_EVEN;
  filter->mode = MPEGTSCRYPTO_MODE_ENCRYPT;
}

static void
mpegtscrypto_finalize (GObject * object)
{
  MpegTSCrypto *filter = GST_MPEGTSCRYPTO (object);

  if (filter->pids)
    g_array_free (filter->pids, TRUE);
  if (filter->odd_key)
    g_free (filter->odd_key);
  if (filter->even_key)
    g_free (filter->even_key);
  if (filter->odd_iv)
    g_free (filter->odd_iv);
  if (filter->even_iv)
    g_free (filter->even_iv);
  if (filter->algo)
    g_free (filter->algo);

  if (G_OBJECT_CLASS (parent_class)->finalize)
    G_OBJECT_CLASS (parent_class)->finalize (object);
}

static inline GstFlowReturn
mpegtscrypto_drain (MpegTSCrypto * filter)
{
  G_GNUC_UNUSED MpegTSCryptoClass *klass = GST_MPEGTSCRYPTO_GET_CLASS (filter);

  return GST_FLOW_OK;
}

static inline void
mpegtscrypto_flush (MpegTSCrypto * filter)
{
  G_GNUC_UNUSED MpegTSCryptoClass *klass = GST_MPEGTSCRYPTO_GET_CLASS (filter);

}

/* GstBaseTransform vmethod implementations */

static GstFlowReturn
mpegtscrypto_transform_ip (GstBaseTransform * base, GstBuffer * buf)
{
  GstFlowReturn res = GST_FLOW_OK;
  MpegTSCrypto *filter;
  MpegTSPacketizerPacketReturn pret;
  MpegTSPacketizer2 *packetizer;
  MpegTSPacketizerPacket pkt;
  guint i;

  filter = GST_MPEGTSCRYPTO (base);
  packetizer = filter->packetizer;

  GST_LOG_OBJECT (filter, "Got buffer size:%ld", gst_buffer_get_size (buf));

  if (GST_BUFFER_IS_DISCONT (buf)) {
    GST_DEBUG_OBJECT (filter, "Got DISCONT buffer, flushing");
    res = mpegtscrypto_drain (filter);
    if (G_UNLIKELY (res != GST_FLOW_OK))
      return res;

    mpegtscrypto_flush (filter);
  }

  mpegts_packetizer_push (packetizer, buf);

  while (res == GST_FLOW_OK) {
    pret = mpegts_packetizer_next_packet (packetizer, &pkt);

    /* If we don't have enough data, return */
    if (G_UNLIKELY (pret == PACKET_NEED_MORE))
      break;

    if (G_UNLIKELY (pret == PACKET_BAD)) {
      /* bad header, skip the packet */
      GST_DEBUG_OBJECT (filter, "bad packet, skipping");
      goto next;
    }

    for (i = 0; i < filter->pids->len; i++) {
        if (g_array_index(filter->pids, gint, i) == pkt.pid) {
            break;
        }
    }

    if (i == filter->pids->len)
      goto next;

    /* process packet */
    if (filter->mode == MPEGTSCRYPTO_MODE_DECRYPT &&
          FLAGS_SCRAMBLED (pkt.scram_afc_cc)) {
      mpegtscrypto_decrypt (filter, &pkt);
    } else if (filter->mode == MPEGTSCRYPTO_MODE_ENCRYPT) {
      mpegtscrypto_encrypt (filter, &pkt);
    }

next:
    mpegts_packetizer_clear_packet (packetizer, &pkt);
  }

  return res;
}

static inline int hex_to_int (gchar c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static inline gboolean
unhexlify (const char *hexstr, unsigned char *buf, size_t len)
{
    size_t hex_len = strlen(hexstr);

    if (hex_len % 2 != 0)
        return FALSE;

    if (len < hex_len / 2)
        return FALSE;

    for (size_t i = 0; i < hex_len / 2; i++) {
        int high_nibble = hex_to_int (hexstr[i * 2]);
        int low_nibble = hex_to_int (hexstr[i * 2 + 1]);

        if (high_nibble == -1 || low_nibble == -1)
            return -1;

        buf[i] = (high_nibble << 4) | low_nibble;
    }

    return TRUE;
}

static gboolean
mpegtscrypto_start (GstBaseTransform * base)
{
  MpegTSCrypto *filter = GST_MPEGTSCRYPTO (base);
  MpegTSCryptoCipherParam *c = NULL;
  const gchar *name = NULL;

  GST_INFO_OBJECT (filter, "Starting");

  name = gst_element_get_name(GST_ELEMENT(filter));
  if (g_str_has_suffix(name, "mpegtsencrypt")) {
    filter->mode = MPEGTSCRYPTO_MODE_ENCRYPT;
  } else if (g_str_has_suffix(name, "mpegtsdecrypt")) {
    filter->mode = MPEGTSCRYPTO_MODE_DECRYPT;
  } else {
    GST_ERROR("Unknown element name: %s", name);
    return FALSE;
  }

  for (c = cipher_list; c->name != NULL; c++) {
    if (g_strcmp0(filter->algo, c->name) == 0) {
      break;
    }
  }

  if (c->name == NULL) {
    GST_ERROR_OBJECT (filter,
        "cipher %s not supported", filter->algo);
    return FALSE;
  }

  if (strlen(filter->odd_key) != c->key_size ||
      strlen(filter->even_key) != c->key_size) {
    GST_ERROR_OBJECT (filter,
      "wrong key size for cipher %s: expected len %d ",
          c->name, c->key_size);
    return FALSE;
  }

  if (c->iv_size > 0) {
    if (strlen(filter->odd_iv) != c->iv_size ||
        strlen(filter->even_iv) != c->iv_size) {
      GST_ERROR_OBJECT (filter,
        "wrong IV size for cipher %s: expected len %d ",
            c->name, c->iv_size);
      return FALSE;
    }
  }

  if (unhexlify(filter->even_key,
      filter->key[0], sizeof(filter->key[0]))) {
    GST_ERROR_OBJECT (filter,
      "error in hex format for even key %s", filter->even_key);
    return FALSE;
  }

  if (unhexlify(filter->odd_key,
      filter->key[1], sizeof(filter->key[1]))) {
    GST_ERROR_OBJECT (filter,
      "error in hex format for even key %s", filter->odd_key);
    return FALSE;
  }

  if (unhexlify(filter->even_iv,
      filter->iv[0], sizeof(filter->iv[0]))) {
    GST_ERROR_OBJECT (filter,
      "error in hex format for even iv %s", filter->even_iv);
    return FALSE;
  }

  if (unhexlify(filter->odd_iv,
      filter->iv[1], sizeof(filter->iv[1]))) {
    GST_ERROR_OBJECT (filter,
      "error in hex format for odd iv %s", filter->odd_iv);
    return FALSE;
  }

  filter->key_size = strlen(filter->even_key) / 2;
  filter->packetizer->packet_size = filter->packet_size;

  if (filter->mode == MPEGTSCRYPTO_MODE_ENCRYPT)
    filter->process = c->encrypt;
  else
    filter->process = c->decrypt;

  gst_base_transform_set_in_place (GST_BASE_TRANSFORM (filter), TRUE);

  GST_INFO_OBJECT (filter, "Start successfull");
  return TRUE;
}

static gboolean
mpegtscrypto_stop (GstBaseTransform * base)
{
  MpegTSCrypto *filter = GST_MPEGTSCRYPTO (base);

  GST_LOG_OBJECT (filter, "Stop successfull");
  return TRUE;
}

static gboolean
mpegtscrypto_encrypt (MpegTSCrypto *filter, MpegTSPacketizerPacket *pkt)
{
  guint len = filter->packet_size - pkt->offset;
  gint key_idx = -1;

  if (len > 0) {
    /* select key based on element parameters */
    if (filter->parity == MPEGTSCRYPTO_PARITY_EVEN ||
        (filter->parity == MPEGTSCRYPTO_PARITY_TSC &&
          MPEGTS_FLAGS_SCRAMBLED_EVEN (pkt->scram_afc_cc))) {
      key_idx = 0;
    }
    else if (filter->parity == MPEGTSCRYPTO_PARITY_ODD ||
        (filter->parity == MPEGTSCRYPTO_PARITY_TSC &&
          MPEGTS_FLAGS_SCRAMBLED_ODD (pkt->scram_afc_cc))) {
      key_idx = 1;
    } else if (filter->parity == MPEGTSCRYPTO_PARITY_AUTO) {

    }

    /* ignore packet for encryption */
    if (key_idx != 0 && key_idx != 1)
      return TRUE;

    /* select even/odd key basd on packet tsc flags */
    filter->cipher.KEY = filter->key[key_idx];
    filter->cipher.IV = filter->iv[key_idx];
    filter->cipher.key_size = filter->key_size;

    /* decryption callback */
    if (filter->process (
                    &filter->cipher,
                    pkt->payload,
                    len,
                    pkt->payload,
                    filter->key_size) < 0) {
      GST_WARNING_OBJECT (filter,
          "call to 'decrypt' for cipher: '%s' failed!", filter->algo);
      return FALSE;
    }

    /* set scrambling control flag for packet */
    if (key_idx == 0)
      pkt->data_start[3] ^= ~0x7f;
    else
      pkt->data_start[3] ^= ~0x3f;
  }

  return TRUE;
}

static gboolean
mpegtscrypto_decrypt (MpegTSCrypto *filter, MpegTSPacketizerPacket *pkt)
{
  guint len = filter->packet_size - pkt->offset;
  guint key_idx = MPEGTS_FLAGS_SCRAMBLED_EVEN (pkt->scram_afc_cc) ? 0 : 1;

  if (MPEGTS_FLAGS_SCRAMBLED (pkt->scram_afc_cc)) {
    if (len > 0) {
      /* select even/odd key basd on packet tsc flags */
      filter->cipher.KEY = filter->key[key_idx];
      filter->cipher.IV = filter->iv[key_idx];
      filter->cipher.key_size = filter->key_size;

      /* decryption callback */
      if (filter->process (
                      &filter->cipher,
                      pkt->payload,
                      len,
                      pkt->payload,
                      filter->key_size) < 0) {
        GST_WARNING_OBJECT (filter,
            "call to 'decrypt' for cipher: '%s' failed!", filter->algo);
        return FALSE;
      }

      /* set scrambling control flag for packet */
      if (filter->tsc_flag == MPEGTSCRYPTO_TSCFLAG_CLEAR)
        pkt->data_start[3] &= 0x3f;
      else if (filter->tsc_flag == MPEGTSCRYPTO_TSCFLAG_EVEN)
        pkt->data_start[3] ^= ~0x7f;
      else if (filter->tsc_flag == MPEGTSCRYPTO_TSCFLAG_ODD)
        pkt->data_start[3] ^= ~0x3f;
    }
  }

  return TRUE;
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
mpegtscrypto_plugin_init (GstPlugin * plugin)
{
  gboolean ret = FALSE;

  ret |= gst_element_register (plugin, "mpegtsdecrypt",
                      GST_RANK_NONE, GST_TYPE_MPEGTSCRYPTO);
  ret |= gst_element_register (plugin, "mpegtsencrypt",
                      GST_RANK_NONE, GST_TYPE_MPEGTSCRYPTO);

  return ret;
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    mpegtscrypto,
    "MPEG-TS Crypto Plugin",
    mpegtscrypto_plugin_init,
    VERSION, "LGPL", "GStreamer",
    "https://github.com/deji-aribuki/gst-mpegtscrypto");
