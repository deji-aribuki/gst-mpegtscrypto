/*
 * mpegtspacketizer.c -
 * Copyright (C) 2007, 2008 Alessandro Decina, Zaheer Merali
 *
 * Authors:
 *   Zaheer Merali <zaheerabbas at merali dot org>
 *   Alessandro Decina <alessandro@nnva.org>
 *   Deji Aribuki <daribuki@ketulabs.ch>, <deji.aribuki@gmail.com>
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

#include <string.h>
#include <stdlib.h>


#include "gstmpegtspacketizer.h"

GST_DEBUG_CATEGORY_STATIC (mpegts_packetizer_debug);
#define GST_CAT_DEFAULT mpegts_packetizer_debug

static void _init_local (void);
G_DEFINE_TYPE_EXTENDED (MpegTSPacketizer2, mpegts_packetizer, G_TYPE_OBJECT, 0,
    _init_local ());


static void mpegts_packetizer_dispose (GObject * object);
static void mpegts_packetizer_finalize (GObject * object);


#define PACKET_SYNC_BYTE 0x47


static void
mpegts_packetizer_class_init (MpegTSPacketizer2Class * klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->dispose = mpegts_packetizer_dispose;
  gobject_class->finalize = mpegts_packetizer_finalize;
}

static void
mpegts_packetizer_init (MpegTSPacketizer2 * packetizer)
{
  g_mutex_init (&packetizer->group_lock);

  packetizer->adapter = gst_adapter_new ();
  packetizer->offset = 0;
  packetizer->empty = TRUE;

  packetizer->map_data = NULL;
  packetizer->map_size = 0;
  packetizer->map_offset = 0;
  packetizer->need_sync = FALSE;
}

static void
mpegts_packetizer_dispose (GObject * object)
{
  MpegTSPacketizer2 *packetizer = GST_MPEGTS_PACKETIZER (object);

  if (!packetizer->disposed) {
    gst_adapter_clear (packetizer->adapter);
    g_object_unref (packetizer->adapter);
    g_mutex_clear (&packetizer->group_lock);
    packetizer->disposed = TRUE;
    packetizer->offset = 0;
    packetizer->empty = TRUE;
  }

  if (G_OBJECT_CLASS (mpegts_packetizer_parent_class)->dispose)
    G_OBJECT_CLASS (mpegts_packetizer_parent_class)->dispose (object);
}

static void
mpegts_packetizer_finalize (GObject * object)
{
  if (G_OBJECT_CLASS (mpegts_packetizer_parent_class)->finalize)
    G_OBJECT_CLASS (mpegts_packetizer_parent_class)->finalize (object);
}

static gboolean
mpegts_packetizer_parse_adaptation_field_control (
        MpegTSPacketizerPacket * packet)
{
  guint8 length, afcflags;
  guint8 *data;

  length = *packet->data++;
  packet->offset++;

  /* an adaptation field with length 0 is valid and
   * can be used to insert a single stuffing byte */
  if (!length) {
    packet->afc_flags = 0;
    return TRUE;
  }

  if ((packet->scram_afc_cc & 0x30) == 0x20) {
    /* no payload, adaptation field of 183 bytes */
    if (length > 183) {
      GST_WARNING ("PID 0x%04x afc == 0x%02x and length %d > 183",
          packet->pid, packet->scram_afc_cc & 0x30, length);
      return FALSE;
    }
    if (length != 183) {
      GST_WARNING ("PID 0x%04x afc == 0x%02x and length %d != 183",
          packet->pid, packet->scram_afc_cc & 0x30, length);
      GST_MEMDUMP ("Unknown payload", packet->data + length,
          packet->data_end - packet->data - length);
    }
  } else if (length == 183) {
    /* Note: According to the specification, the adaptation field length
     * must be 183 if there is no payload data and < 183 if the packet
     * contains an adaptation field and payload data.
     * Some payloaders always set the flag for payload data, even if the
     * adaptation field length is 183. This just means a zero length
     * payload so we clear the payload flag here and continue.
     */
    GST_DEBUG ("PID 0x%04x afc == 0x%02x and length %d == 183 (ignored)",
        packet->pid, packet->scram_afc_cc & 0x30, length);
    packet->scram_afc_cc &= ~0x10;
  } else if (length > 182) {
    GST_WARNING ("PID 0x%04x afc == 0x%02x and length %d > 182",
        packet->pid, packet->scram_afc_cc & 0x30, length);
    return FALSE;
  }

  if (packet->data + length > packet->data_end) {
    GST_DEBUG
        ("PID 0x%04x afc length %d overflows the buffer current %d max %d",
        packet->pid, length, (gint) (packet->data - packet->data_start),
        (gint) (packet->data_end - packet->data_start));
    return FALSE;
  }

  data = packet->data;
  packet->data += length;
  packet->offset += length;

  afcflags = packet->afc_flags = *data++;

  packet->offset++;

  GST_DEBUG ("flags: %s%s%s%s%s%s%s%s%s",
      afcflags & 0x80 ? "discontinuity " : "",
      afcflags & 0x40 ? "random_access " : "",
      afcflags & 0x20 ? "elementary_stream_priority " : "",
      afcflags & 0x10 ? "PCR " : "",
      afcflags & 0x08 ? "OPCR " : "",
      afcflags & 0x04 ? "splicing_point " : "",
      afcflags & 0x02 ? "transport_private_data " : "",
      afcflags & 0x01 ? "extension " : "", afcflags == 0x00 ? "<none>" : "");

  return TRUE;
}

static MpegTSPacketizerPacketReturn
mpegts_packetizer_parse_packet (
        G_GNUC_UNUSED MpegTSPacketizer2 * packetizer,
        MpegTSPacketizerPacket * packet)
{
  guint8 *data;
  guint8 tmp;

  data = packet->data_start;
  data += 1;
  tmp = *data;

  /* transport_error_indicator 1 */
  if (G_UNLIKELY (tmp & 0x80))
    return PACKET_BAD;

  /* payload_unit_start_indicator 1 */
  packet->payload_unit_start_indicator = tmp & 0x40;

  /* transport_priority 1 */
  /* PID 13 */
  packet->pid = GST_READ_UINT16_BE (data) & 0x1FFF;
  data += 2;

  packet->scram_afc_cc = tmp = *data++;
  /* transport_scrambling_control 2 */
  // if (G_UNLIKELY (tmp & 0xc0))
  //   return PACKET_BAD;

  packet->data = data;

  packet->afc_flags = 0;
  packet->offset = 4;

  if (FLAGS_HAS_AFC (tmp)) {
    if (!mpegts_packetizer_parse_adaptation_field_control (packet))
      return PACKET_BAD;
  }

  if (FLAGS_HAS_PAYLOAD (packet->scram_afc_cc))
    packet->payload = packet->data;
  else
    packet->payload = NULL;

  return PACKET_OK;
}

void
mpegts_packetizer_clear (MpegTSPacketizer2 * packetizer)
{
  packetizer->packet_size = 0;

  gst_adapter_clear (packetizer->adapter);
  packetizer->offset = 0;
  packetizer->empty = TRUE;
  packetizer->need_sync = FALSE;
  packetizer->map_data = NULL;
  packetizer->map_size = 0;
  packetizer->map_offset = 0;
}

MpegTSPacketizer2 *
mpegts_packetizer_new (void)
{
  MpegTSPacketizer2 *packetizer;

  packetizer =
      GST_MPEGTS_PACKETIZER (g_object_new (GST_TYPE_MPEGTS_PACKETIZER, NULL));

  return packetizer;
}

void
mpegts_packetizer_push (MpegTSPacketizer2 * packetizer, GstBuffer * buffer)
{
  if (G_UNLIKELY (packetizer->empty)) {
    packetizer->empty = FALSE;
    packetizer->offset = GST_BUFFER_OFFSET (buffer);
  }

  GST_DEBUG ("Pushing %" G_GSIZE_FORMAT " byte from offset %"
      G_GUINT64_FORMAT, gst_buffer_get_size (buffer),
      GST_BUFFER_OFFSET (buffer));
  gst_adapter_push (packetizer->adapter, buffer);
}

static void
mpegts_packetizer_flush_bytes (MpegTSPacketizer2 * packetizer, gsize size)
{
  if (size > 0) {
    GST_LOG ("flushing %" G_GSIZE_FORMAT " bytes from adapter", size);
    gst_adapter_flush (packetizer->adapter, size);
  }

  packetizer->map_data = NULL;
  packetizer->map_size = 0;
  packetizer->map_offset = 0;
}

static gboolean
mpegts_packetizer_map (MpegTSPacketizer2 * packetizer, gsize size)
{
  gsize available;

  if (packetizer->map_size - packetizer->map_offset >= size)
    return TRUE;

  mpegts_packetizer_flush_bytes (packetizer, packetizer->map_offset);

  available = gst_adapter_available (packetizer->adapter);
  if (available < size)
    return FALSE;

  packetizer->map_data =
      (guint8 *) gst_adapter_map (packetizer->adapter, available);
  if (!packetizer->map_data)
    return FALSE;

  packetizer->map_size = available;
  packetizer->map_offset = 0;

  GST_LOG ("mapped %" G_GSIZE_FORMAT " bytes from adapter", available);

  return TRUE;
}

static gboolean
mpegts_packetizer_sync (MpegTSPacketizer2 * packetizer)
{
  gboolean found = FALSE;
  guint8 *data;
  guint packet_size;
  gsize size, sync_offset, i;

  packet_size = packetizer->packet_size;

  if (!mpegts_packetizer_map (packetizer, 3 * packet_size))
    return FALSE;

  size = packetizer->map_size - packetizer->map_offset;
  data = packetizer->map_data + packetizer->map_offset;

  if (packet_size == MPEGTS_M2TS_PACKETSIZE)
    sync_offset = 4;
  else
    sync_offset = 0;

  for (i = sync_offset; i + 2 * packet_size < size; i++) {
    if (data[i] == PACKET_SYNC_BYTE &&
        data[i + packet_size] == PACKET_SYNC_BYTE &&
        data[i + 2 * packet_size] == PACKET_SYNC_BYTE) {
      found = TRUE;
      break;
    }
  }

  packetizer->map_offset += i - sync_offset;

  if (!found)
    mpegts_packetizer_flush_bytes (packetizer, packetizer->map_offset);

  return found;
}

MpegTSPacketizerPacketReturn
mpegts_packetizer_next_packet (MpegTSPacketizer2 * packetizer,
    MpegTSPacketizerPacket * packet)
{
  guint8 *packet_data;
  guint packet_size;
  gsize sync_offset;

  packet_size = packetizer->packet_size;

  /* M2TS packets don't start with the sync byte, all other variants do */
  if (packet_size == MPEGTS_M2TS_PACKETSIZE)
    sync_offset = 4;
  else
    sync_offset = 0;

  while (1) {
    if (packetizer->need_sync) {
      if (!mpegts_packetizer_sync (packetizer))
        return PACKET_NEED_MORE;
      packetizer->need_sync = FALSE;
    }

    if (!mpegts_packetizer_map (packetizer, packet_size))
      return PACKET_NEED_MORE;

    packet_data = &packetizer->map_data[packetizer->map_offset + sync_offset];

    /* Check sync byte */
    if (G_UNLIKELY (*packet_data != PACKET_SYNC_BYTE)) {
      GST_DEBUG ("lost sync");
      packetizer->need_sync = TRUE;
    } else {
      /* ALL mpeg-ts variants contain 188 bytes of data. Those with bigger
       * packet sizes contain either extra data (timesync, FEC, ..) either
       * before or after the data */
      packet->data_start = packet_data;
      packet->data_end = packet->data_start + 188;
      // packet->offset = packetizer->offset;
      // GST_LOG ("offset %" G_GUINT64_FORMAT, packet->offset);
      // packetizer->offset += packet_size;
      GST_MEMDUMP ("data_start", packet->data_start, 16);

      return mpegts_packetizer_parse_packet (packetizer, packet);
    }
  }
}

void
mpegts_packetizer_clear_packet (MpegTSPacketizer2 * packetizer,
    G_GNUC_UNUSED MpegTSPacketizerPacket * packet)
{
  guint8 packet_size = packetizer->packet_size;

  if (packetizer->map_data) {
    packetizer->map_offset += packet_size;
    if (packetizer->map_size - packetizer->map_offset < packet_size)
      mpegts_packetizer_flush_bytes (packetizer, packetizer->map_offset);
  }
}

gboolean
mpegts_packetizer_has_packets (MpegTSPacketizer2 * packetizer)
{
  // if (G_UNLIKELY (!packetizer->packet_size)) {
  //   if (!mpegts_try_discover_packet_size (packetizer))
  //     return FALSE;
  // }
  return gst_adapter_available (packetizer->adapter) >= packetizer->packet_size;
}

static void
_init_local (void)
{
  GST_DEBUG_CATEGORY_INIT (mpegts_packetizer_debug, "mpegtspacketizer", 0,
      "MPEG transport stream parser");
}