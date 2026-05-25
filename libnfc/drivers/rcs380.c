/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

/**
 * @file rcs380.c
 * @brief Driver for Sony RC-S380 PaSoRi using the NFC Port-100 protocol
 */

/*
 * This implementation was written based on the nfcpy project's open-source
 * reference implementation for the Sony RC-S380 (NFC Port-100 protocol):
 *
 * nfcpy - A Python implementation of the NFC standard
 * https://github.com/nfcpy/nfcpy
 * nfc/clf/rcs380.py
 *
 * NFC Port-100 protocol details (command codes, frame format, InSetProtocol
 * parameter IDs and default values, InCommRF response layout) were all
 * derived from that reference.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <stdatomic.h>
#ifdef _MSC_VER
#  include <sys/types.h>
#endif

#include <nfc/nfc.h>

#include "rcs380.h"
#include "drivers.h"
#include "nfc-internal.h"
#include "../buses/usbbus.h"

#define RCS380_DRIVER_NAME "rcs380"
#define LOG_CATEGORY "libnfc.driver.rcs380"
#define LOG_GROUP    NFC_LOG_GROUP_DRIVER

#define DRIVER_DATA(pnd) ((struct rcs380_data *)((pnd)->driver_data))

// USB device constants
#define RCS380_USB_VENDOR_ID   0x054C
#define RCS380_USB_PRODUCT_ID  0x06C3
#define RCS380_USB_EP_OUT      0x02
#define RCS380_USB_EP_IN       0x81
#define RCS380_USB_TIMEOUT     1000  // ms, for control commands
#define RCS380_USB_IO_TIMEOUT  5000  // ms, for InCommRF reads
// Per-pass USB read budget; smaller passes let nfc_abort_command() interrupt
// pending bulk reads (mirrors pn53x_usb's USB_TIMEOUT_PER_PASS).
#define RCS380_USB_TIMEOUT_PER_PASS 200

// NFC Port-100 frame constants
#define RCS380_TFI_HOST_TO_DEV  0xD6
#define RCS380_TFI_DEV_TO_HOST  0xD7
/*
 * Largest Port-100 frame we build or accept, in bytes.
 *
 * Extended-frame overhead is 12 bytes:
 *   preamble+start+ext-indicator (5) + LEN_L/H (2) + LCS (1)
 *   + TFI (1) + CMD (1) + DCS (1) + postamble (1) = 12.
 *
 * The bounding command in this driver is InCommRF: 2-byte timeout +
 * up to 256-byte tx payload = 258 bytes of CMD-data.  Frame total =
 * 12 + 258 = 270.  InCommRF responses (STATUS 4 + metadata 1 +
 * received RF data) observed from RC-S380 stay well under this same
 * 258 cap, which matches the Port-100 protocol limit per nfcpy's
 * reference implementation (nfc/clf/rcs380.py, _send_command and
 * in_comm_rf).  Any larger frame is rejected by rcs380_recv_frame
 * with NFC_EOVFLOW rather than overrunning this buffer.
 */
#define RCS380_MAX_FRAME_LEN    270

// NFC Port-100 commands (see nfcpy nfc/clf/rcs380.py)
#define RCS380_CMD_IN_SET_RF      0x00
#define RCS380_CMD_IN_SET_PROTO   0x02
#define RCS380_CMD_IN_COMM_RF     0x04
#define RCS380_CMD_SWITCH_RF      0x06
#define RCS380_CMD_GET_FW_VER     0x20
#define RCS380_CMD_GET_PD_DATA    0x22
#define RCS380_CMD_GET_CMD_TYPE   0x28  // query supported command type bitmask
#define RCS380_CMD_SET_CMD_TYPE   0x2A  // set command type (0=compat, 1=NFC Port-100)

// InCommRF error flags, encoded as LE uint32 in the first 4 response bytes
#define RCS380_ERR_PROTOCOL   0x00000001u
#define RCS380_ERR_PARITY     0x00000002u
#define RCS380_ERR_CRC        0x00000004u
#define RCS380_ERR_TIMEOUT    0x00000080u
#define RCS380_ERR_RF_OFF     0x00000400u

// InSetProtocol parameter IDs (see nfcpy in_set_protocol / in_set_protocol_defaults)
#define PROTO_INITIAL_GUARD   0x00
#define PROTO_ADD_CRC         0x01
#define PROTO_CHECK_CRC       0x02
#define PROTO_MULTI_CARD      0x03
#define PROTO_ADD_PARITY      0x04
#define PROTO_CHECK_PARITY    0x05
#define PROTO_BITWISE_ANTICOL 0x06
#define PROTO_LAST_BITS       0x07
#define PROTO_MIFARE_CRYPTO   0x08
#define PROTO_ADD_SOF         0x09
#define PROTO_CHECK_SOF       0x0A
#define PROTO_ADD_EOF         0x0B
#define PROTO_CHECK_EOF       0x0C
#define PROTO_CRM             0x0E
#define PROTO_CRM_MIN_LEN     0x0F
#define PROTO_T1T_RRDD        0x10
#define PROTO_RFCA            0x11
#define PROTO_GUARD_TIME      0x12
#define PROTO_ADD_GUARD_TIME  0x13

// ISO14443A cascade tag indicator byte
#define ISO14443A_CT          0x88

// Internal data struct
struct rcs380_data {
  usb_dev_handle  *udh;
  atomic_bool      abort_flag;
};

// Supported modulations
static const nfc_modulation_type rcs380_initiator_modulations[] = {
  NMT_ISO14443A,
  NMT_FELICA,
  NMT_ISO14443B,
  0
};
static const nfc_modulation_type rcs380_no_target_modulations[] = { 0 };

static const nfc_baud_rate rcs380_iso14443a_baud_rates[] = { NBR_106, 0 };
static const nfc_baud_rate rcs380_felica_baud_rates[]    = { NBR_212, NBR_424, 0 };
static const nfc_baud_rate rcs380_iso14443b_baud_rates[] = { NBR_106, 0 };

/*
 * Protocol configuration tables: (param_id, value) pairs for InSetProtocol.
 * Parameter values and defaults are derived from nfcpy's in_set_protocol_defaults.
 */

// 106A REQA mode: 7-bit last byte, no CRC, check parity, no bitwise anticol
// INITIAL_GUARD_TIME=6 matches nfcpy sense_tta(initial_guard_time=6)
static const uint8_t proto_106a_reqa[] = {
  PROTO_INITIAL_GUARD,   0x06,
  PROTO_ADD_CRC,         0x00,
  PROTO_CHECK_CRC,       0x00,
  PROTO_MULTI_CARD,      0x00,
  PROTO_ADD_PARITY,      0x00,
  PROTO_CHECK_PARITY,    0x01,
  PROTO_BITWISE_ANTICOL, 0x00,
  PROTO_LAST_BITS,       0x07,
  PROTO_MIFARE_CRYPTO,   0x00,
  PROTO_ADD_SOF,         0x00,
  PROTO_CHECK_SOF,       0x00,
  PROTO_ADD_EOF,         0x00,
  PROTO_CHECK_EOF,       0x00,
  PROTO_CRM,             0x04,
  PROTO_CRM_MIN_LEN,     0x00,
  PROTO_T1T_RRDD,        0x00,
  PROTO_RFCA,            0x00,
  PROTO_GUARD_TIME,      0x00,
  PROTO_ADD_GUARD_TIME,  0x06,
};

// 106A SDD mode: byte frames, parity on, no CRC
static const uint8_t proto_106a_sdd[] = {
  PROTO_ADD_PARITY,      0x01,
  PROTO_CHECK_PARITY,    0x01,
  PROTO_BITWISE_ANTICOL, 0x00,
  PROTO_LAST_BITS,       0x08,
};

// 106A SELECT mode: CRC on
static const uint8_t proto_106a_select[] = {
  PROTO_ADD_CRC,   0x01,
  PROTO_CHECK_CRC, 0x01,
};

// 106A data exchange mode: CRC + parity, full bytes
static const uint8_t proto_106a_data[] = {
  PROTO_ADD_CRC,         0x01,
  PROTO_CHECK_CRC,       0x01,
  PROTO_ADD_PARITY,      0x01,
  PROTO_CHECK_PARITY,    0x01,
  PROTO_BITWISE_ANTICOL, 0x00,
  PROTO_LAST_BITS,       0x08,
};

// FeliCa protocol
// ADD_GUARD_TIME=6 matches nfcpy default guard_time_at_initiator=6
static const uint8_t proto_felica[] = {
  PROTO_INITIAL_GUARD,   0x18,
  PROTO_ADD_CRC,         0x01,
  PROTO_CHECK_CRC,       0x01,
  PROTO_MULTI_CARD,      0x00,
  PROTO_ADD_PARITY,      0x00,
  PROTO_CHECK_PARITY,    0x00,
  PROTO_BITWISE_ANTICOL, 0x00,
  PROTO_LAST_BITS,       0x08,
  PROTO_MIFARE_CRYPTO,   0x00,
  PROTO_ADD_SOF,         0x00,
  PROTO_CHECK_SOF,       0x00,
  PROTO_ADD_EOF,         0x00,
  PROTO_CHECK_EOF,       0x00,
  PROTO_CRM,             0x04,
  PROTO_CRM_MIN_LEN,     0x00,
  PROTO_T1T_RRDD,        0x00,
  PROTO_RFCA,            0x00,
  PROTO_GUARD_TIME,      0x00,
  PROTO_ADD_GUARD_TIME,  0x06,
};

// ISO14443B protocol
static const uint8_t proto_106b[] = {
  PROTO_INITIAL_GUARD,   0x14,
  PROTO_ADD_CRC,         0x01,
  PROTO_CHECK_CRC,       0x01,
  PROTO_MULTI_CARD,      0x00,
  PROTO_ADD_PARITY,      0x00,
  PROTO_CHECK_PARITY,    0x00,
  PROTO_BITWISE_ANTICOL, 0x00,
  PROTO_LAST_BITS,       0x08,
  PROTO_MIFARE_CRYPTO,   0x00,
  PROTO_ADD_SOF,         0x01,
  PROTO_CHECK_SOF,       0x01,
  PROTO_ADD_EOF,         0x01,
  PROTO_CHECK_EOF,       0x01,
  PROTO_CRM,             0x04,
  PROTO_CRM_MIN_LEN,     0x00,
  PROTO_T1T_RRDD,        0x00,
  PROTO_RFCA,            0x00,
  PROTO_GUARD_TIME,      0x00,
  PROTO_ADD_GUARD_TIME,  0x14,
};

// USB bulk I/O

static int
rcs380_bulk_write(usb_dev_handle *udh, const uint8_t *data, size_t len, int timeout)
{
  int res = usb_bulk_write(udh, RCS380_USB_EP_OUT, (char *)data, (int)len, timeout);
  if (res > 0) {
    LOG_HEX(NFC_LOG_GROUP_COM, "TX", data, (size_t)res);
  } else if (res < 0) {
    log_put(NFC_LOG_GROUP_COM, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "Unable to write to USB (%s)", _usb_strerror(res));
  }
  return res;
}

static int
rcs380_bulk_read(usb_dev_handle *udh, uint8_t *data, size_t max_len, int timeout)
{
  int res = usb_bulk_read(udh, RCS380_USB_EP_IN, (char *)data, (int)max_len, timeout);
  if (res > 0) {
    LOG_HEX(NFC_LOG_GROUP_COM, "RX", data, (size_t)res);
  } else if (res < 0 && res != -USB_TIMEDOUT) {
    log_put(NFC_LOG_GROUP_COM, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "Unable to read from USB (%s)", _usb_strerror(res));
  }
  return res;
}

// NFC Port-100 frame encode / decode

/*
 * Build a NFC Port-100 extended frame into buf.  Returns total frame length.
 * buf must be at least RCS380_MAX_FRAME_LEN bytes (10 + 2 + data_len + 2).
 * Callers are responsible for ensuring data_len does not exceed
 * RCS380_MAX_FRAME_LEN - 12 (currently 258).
 *
 * Frame layout (see nfcpy rcs380.py _send_command):
 *   [00 00 FF FF FF] [LEN_L LEN_H LCS] [D6 cmd data...] [DCS] [00]
 *    0  1   2  3  4   5     6    7       8   9   10+
 */
static size_t
rcs380_build_frame(uint8_t *buf, uint8_t cmd, const uint8_t *data, size_t data_len)
{
  size_t payload_len = 2 + data_len;  // TFI + CMD + data

  buf[0] = 0x00;  // preamble
  buf[1] = 0x00;  // start code
  buf[2] = 0xFF;  // start code
  buf[3] = 0xFF;  // extended frame indicator
  buf[4] = 0xFF;  // extended frame indicator
  buf[5] = (uint8_t)(payload_len & 0xFF);           // LEN_L
  buf[6] = (uint8_t)((payload_len >> 8) & 0xFF);    // LEN_H
  buf[7] = (uint8_t)((256 - buf[5] - buf[6]) & 0xFF); // LCS
  buf[8] = RCS380_TFI_HOST_TO_DEV;                  // D6
  buf[9] = cmd;
  if (data_len > 0)
    memcpy(buf + 10, data, data_len);

  unsigned int sum = 0;
  for (size_t i = 8; i < 8 + payload_len; i++)
    sum += buf[i];
  buf[8 + payload_len] = (uint8_t)((256 - sum) & 0xFF); // DCS
  buf[9 + payload_len] = 0x00;                           // postamble

  return 10 + payload_len;
}

/*
 * Parse a received NFC Port-100 extended frame.  Validates magic, lengths,
 * checksums, TFI, and expected response command (exp_cmd + 1).
 * Copies the payload data (excluding D7 and CMD+1 bytes) into out.
 * Returns payload data length, or < 0 on error.
 */
static int
rcs380_parse_frame(const uint8_t *frame, size_t frame_len,
                   uint8_t exp_cmd, uint8_t *out, size_t out_max)
{
  // Frame can be either short frame or extended frame.
  // Short frame:  [00 00 FF] [LEN] [LCS] [TFI CMD...] [DCS] [POST]
  // Extended:    [00 00 FF FF FF] [LEN_L LEN_H LCS] [TFI CMD...] [DCS] [POST]

  if (frame_len < 6) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "Frame too short (%zu bytes)", frame_len);
    return NFC_EIO;
  }

  if (frame[0] != 0x00 || frame[1] != 0x00 || frame[2] != 0xFF) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "Frame magic mismatch (%02X %02X %02X)",
            frame[0], frame[1], frame[2]);
    return NFC_EIO;
  }

  // Extended frame detection: next two bytes are 0xFF 0xFF (frame_len >= 6 guaranteed above)
  if (frame[3] == 0xFF && frame[4] == 0xFF) {
    if (frame_len < 13) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
              "Extended frame too short (%zu bytes)", frame_len);
      return NFC_EIO;
    }
    uint16_t payload_len = (uint16_t)frame[5] | ((uint16_t)frame[6] << 8);
    uint8_t lcs = (uint8_t)((256 - frame[5] - frame[6]) & 0xFF);
    if (frame[7] != lcs) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
              "LCS mismatch (got %02X, expected %02X)", frame[7], lcs);
      return NFC_EIO;
    }
    if ((size_t)(10 + payload_len) > frame_len) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
              "%s", "Frame length field exceeds received data");
      return NFC_EIO;
    }
    if (frame[8] != RCS380_TFI_DEV_TO_HOST) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
              "Unexpected TFI %02X (expected D7)", frame[8]);
      return NFC_EIO;
    }
    if (frame[9] != (uint8_t)(exp_cmd + 1)) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
              "Unexpected response code %02X (expected %02X)",
              frame[9], (uint8_t)(exp_cmd + 1));
      return NFC_EIO;
    }
    unsigned int sum = 0;
    for (size_t i = 8; i < (size_t)(8 + payload_len); i++)
      sum += frame[i];
    uint8_t dcs = (uint8_t)((256 - sum) & 0xFF);
    if (frame[8 + payload_len] != dcs) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
              "DCS mismatch (got %02X, expected %02X)",
              frame[8 + payload_len], dcs);
      return NFC_EIO;
    }
    // Postamble must be 0x00 per the Port-100 frame format
    if (frame[9 + payload_len] != 0x00) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
              "Postamble mismatch (got %02X, expected 00)",
              frame[9 + payload_len]);
      return NFC_EIO;
    }
    size_t data_len = payload_len >= 2 ? (size_t)(payload_len - 2) : 0;
    if (data_len > out_max) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
              "Response data too large (%zu bytes)", data_len);
      return NFC_EOVFLOW;
    }
    if (out && data_len > 0)
      memcpy(out, frame + 10, data_len);
    return (int)data_len;
  }

  // Short frame handling
  uint8_t payload_len = frame[3];
  uint8_t lcs = (uint8_t)((256 - payload_len) & 0xFF);
  if (frame[4] != lcs) {
    // ACK (00 00 FF 00 FF 00) is intercepted by recv_frame before parse_frame is called.
    // An LCS mismatch here means a corrupt frame, not a valid ACK.
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "LCS mismatch in short frame (got %02X, expected %02X)", frame[4], lcs);
    return NFC_EIO;
  }
  // total expected = 7 + payload_len (3 magic + LEN + LCS + payload_len + DCS + POST)
  if ((size_t)(7 + payload_len) > frame_len) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "%s", "Frame length field exceeds received data (short)");
    return NFC_EIO;
  }
  if (frame[5] != RCS380_TFI_DEV_TO_HOST) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "Unexpected TFI %02X (expected D7)", frame[5]);
    return NFC_EIO;
  }
  if (frame[6] != (uint8_t)(exp_cmd + 1)) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "Unexpected response code %02X (expected %02X)",
            frame[6], (uint8_t)(exp_cmd + 1));
    return NFC_EIO;
  }
  unsigned int sum2 = 0;
  for (size_t i = 5; i < (size_t)(5 + payload_len); i++)
    sum2 += frame[i];
  uint8_t dcs2 = (uint8_t)((256 - sum2) & 0xFF);
  if (frame[5 + payload_len] != dcs2) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "DCS mismatch (got %02X, expected %02X)", frame[5 + payload_len], dcs2);
    return NFC_EIO;
  }
  // Postamble must be 0x00 per the Port-100 frame format
  if (frame[6 + payload_len] != 0x00) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "Postamble mismatch (got %02X, expected 00)",
            frame[6 + payload_len]);
    return NFC_EIO;
  }
  size_t data_len2 = payload_len >= 2 ? (size_t)(payload_len - 2) : 0;
  if (data_len2 > out_max) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "Response data too large (%zu bytes)", data_len2);
    return NFC_EOVFLOW;
  }
  if (out && data_len2 > 0)
    memcpy(out, frame + 7, data_len2);
  return (int)data_len2;
}

// Send ACK (soft reset) frame: 00 00 FF 00 FF 00
static int
rcs380_send_ack(usb_dev_handle *udh)
{
  static const uint8_t ack[] = { 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00 };
  int res = rcs380_bulk_write(udh, ack, sizeof(ack), RCS380_USB_TIMEOUT);
  return res >= 0 ? NFC_SUCCESS : NFC_EIO;
}

/*
 * Read up to max_len bytes from the device while remaining responsive to
 * nfc_abort_command().  The USB wait is split into USB_TIMEOUT_PER_PASS
 * chunks; between passes we check the atomic abort_flag and, when set,
 * send the soft-reset ACK to interrupt any in-progress device operation
 * (same approach as pn53x_usb's bulk_read loop).
 *
 * Returns:
 *   > 0            bytes read
 *   NFC_EOPABORTED abort requested during this read
 *   NFC_ETIMEOUT   no data within timeout_ms (and no abort requested)
 *   NFC_EIO        other USB error
 */
static int
rcs380_recv_chunked(nfc_device *pnd, uint8_t *buf, size_t max_len, int timeout_ms)
{
  usb_dev_handle *udh = DRIVER_DATA(pnd)->udh;
  int remaining = timeout_ms > 0 ? timeout_ms : RCS380_USB_IO_TIMEOUT;

  for (;;) {
    int pass = remaining < RCS380_USB_TIMEOUT_PER_PASS
                 ? remaining
                 : RCS380_USB_TIMEOUT_PER_PASS;
    int res = rcs380_bulk_read(udh, buf, max_len, pass);
    if (res > 0)
      return res;

    if (res == -USB_TIMEDOUT) {
      if (atomic_exchange(&DRIVER_DATA(pnd)->abort_flag, false)) {
        rcs380_send_ack(udh);
        return NFC_EOPABORTED;
      }
      remaining -= pass;
      if (remaining <= 0)
        return NFC_ETIMEOUT;
      continue;
    }

    return NFC_EIO;
  }
}

/*
 * Read a complete NFC Port-100 frame, accumulating multiple USB packets.
 * The device's EP IN has a small max-packet-size (8 bytes) so a single
 * 13-byte response may arrive as two separate USB bulk transfers.
 *
 * Returns total bytes accumulated, or a negative NFC_E* code on failure
 * (NFC_ETIMEOUT / NFC_EOPABORTED / NFC_EIO / NFC_EOVFLOW).
 */
static int
rcs380_recv_frame(nfc_device *pnd, uint8_t *buf, size_t buf_max, int timeout_ms)
{
  size_t total = 0;
  static const uint8_t ack_pattern[] = { 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00 };
  bool found_magic = false;

  while (total < buf_max) {
    int res = rcs380_recv_chunked(pnd, buf + total, buf_max - total, timeout_ms);
    if (res < 0) {
      // Propagate normalized NFC_E* code (NFC_ETIMEOUT / NFC_EOPABORTED / NFC_EIO)
      return res;
    }

    total += (size_t)res;

    // Search for short/extended frame magic 00 00 FF
    size_t magic_pos = SIZE_MAX;
    if (total >= 3) {
      for (size_t i = 0; i + 2 < total; i++) {
        if (buf[i] == 0x00 && buf[i + 1] == 0x00 && buf[i + 2] == 0xFF) {
          magic_pos = i;
          break;
        }
      }
    }

    if (magic_pos == SIZE_MAX)
      continue;

    found_magic = true;

    if (magic_pos > 0) {
      memmove(buf, buf + magic_pos, total - magic_pos);
      total -= magic_pos;
    }

    // If we have an ACK (6 bytes), return it immediately to let caller handle it
    if (total >= 6 && memcmp(buf, ack_pattern, 6) == 0)
      return 6;

    // Need at least 5 bytes to inspect short-frame LEN or to detect extended magic
    if (total < 5)
      continue;

    // Extended frame? check bytes 3 and 4 == 0xFF
    if (buf[3] == 0xFF && buf[4] == 0xFF) {
      // Need LEN_L and LEN_H at 5/6 and LCS at 7
      if (total < 8)
        continue;
      size_t payload_len = (size_t)buf[5] | ((size_t)buf[6] << 8);
      if (buf_max < 10 || payload_len > buf_max - 10) {
        log_put(NFC_LOG_GROUP_COM, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
                "Extended frame payload_len %zu exceeds buffer (%zu)", payload_len, buf_max);
        return NFC_EOVFLOW;
      }
      size_t expected = 10 + payload_len; // 5 magic + 2 len +1 lcs + payload + dcs + post
      while (total < expected && total < buf_max) {
        res = rcs380_recv_chunked(pnd, buf + total, buf_max - total, timeout_ms);
        if (res < 0)
          return res;
        total += (size_t)res;
      }
      return (int)total;
    }

    // Short frame: LEN at buf[3]
    uint8_t payload_len = buf[3];
    // Special-case: if payload_len==0 the ACK frame uses a non-standard LCS (0xFF)
    size_t expected = 7 + payload_len; // 3 magic + LEN + LCS + payload + DCS + POST
    while (total < expected && total < buf_max) {
      res = rcs380_recv_chunked(pnd, buf + total, buf_max - total, timeout_ms);
      if (res < 0)
        return res;
      total += (size_t)res;
    }
    return (int)total;
  }

  // Buffer filled without forming a recognized frame
  if (!found_magic)
    return NFC_ETIMEOUT;
  return (int)total;
}

/*
 * Send a NFC Port-100 command and receive the parsed response payload.
 * resp_out receives the payload data (status bytes + any response content).
 * Returns payload data length, or < 0 on error.
 */
static int
rcs380_cmd(nfc_device *pnd, uint8_t cmd,
           const uint8_t *params, size_t params_len,
           uint8_t *resp_out, size_t resp_max,
           int read_timeout_ms)
{
  int timeout = read_timeout_ms > 0 ? read_timeout_ms : RCS380_USB_TIMEOUT;

  uint8_t frame[RCS380_MAX_FRAME_LEN];
  size_t frame_len = rcs380_build_frame(frame, cmd, params, params_len);

  int res = rcs380_bulk_write(DRIVER_DATA(pnd)->udh, frame, frame_len,
                              RCS380_USB_TIMEOUT);
  if (res < 0) {
    pnd->last_error = NFC_EIO;
    return NFC_EIO;
  }

  static const uint8_t ack_pattern[] = { 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00 };
  uint8_t rbuf[RCS380_MAX_FRAME_LEN];
  int rlen = rcs380_recv_frame(pnd, rbuf, sizeof(rbuf), timeout);
  if (rlen < 0) {
    pnd->last_error = rlen;
    return rlen;
  }

  // Device may send an ACK (6 bytes) before the actual response; skip it
  if (rlen == 6 && memcmp(rbuf, ack_pattern, 6) == 0) {
    rlen = rcs380_recv_frame(pnd, rbuf, sizeof(rbuf), timeout);
    if (rlen < 0) {
      pnd->last_error = rlen;
      return rlen;
    }
  }

  res = rcs380_parse_frame(rbuf, (size_t)rlen, cmd, resp_out, resp_max);
  if (res < 0) {
    pnd->last_error = res;
    return res;
  }
  return res;
}

// Send a command and verify the first response byte is STATUS == 0x00
static int
rcs380_simple_cmd(nfc_device *pnd, uint8_t cmd,
                  const uint8_t *params, size_t params_len)
{
  uint8_t resp[16];
  int res = rcs380_cmd(pnd, cmd, params, params_len,
                       resp, sizeof(resp), RCS380_USB_TIMEOUT);
  if (res < 0)
    return res;
  if (res < 1 || resp[0] != 0x00) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "Command %02X failed (status %02X)", cmd, res >= 1 ? resp[0] : 0xFF);
    pnd->last_error = NFC_ECHIP;
    return NFC_ECHIP;
  }
  return NFC_SUCCESS;
}

// Protocol-level commands

static int
rcs380_switch_rf(nfc_device *pnd, bool on)
{
  uint8_t param = on ? 0x01 : 0x00;
  return rcs380_simple_cmd(pnd, RCS380_CMD_SWITCH_RF, &param, 1);
}

static int
rcs380_set_rf(nfc_device *pnd,
              uint8_t brty_tx_l, uint8_t brty_tx_h,
              uint8_t guard,     uint8_t brty_rx)
{
  const uint8_t params[] = { brty_tx_l, brty_tx_h, guard, brty_rx };
  return rcs380_simple_cmd(pnd, RCS380_CMD_IN_SET_RF, params, sizeof(params));
}

static int
rcs380_set_protocol(nfc_device *pnd, const uint8_t *proto_params, size_t len)
{
  return rcs380_simple_cmd(pnd, RCS380_CMD_IN_SET_PROTO, proto_params, len);
}

/*
 * Send RF data (InCommRF) and receive response.
 *
 * timeout_ms: RF-level timeout passed to the device (100 µs units internally),
 *             or <= 0 for 0xFFFF (maximum).  Derived from nfcpy in_comm_rf:
 *             device_timeout = (timeout_ms + 1) * 10 (100 µs units).
 * usb_timeout_ms: USB read timeout for the host-side bulk read.
 *
 * Returns received data length (excluding 5-byte STATUS+metadata prefix), or < 0.
 *
 * InCommRF response layout (see nfcpy rcs380.py in_comm_rf):
 *   byte 0-3: STATUS as LE uint32 (0 = success, 0x80 = RF timeout)
 *   byte 4:   metadata (received count, etc.) — ignored
 *   byte 5+:  received RF data
 */
static int
rcs380_in_comm_rf(nfc_device *pnd,
                  int timeout_ms,
                  const uint8_t *tx, size_t tx_len,
                  uint8_t *rx, size_t rx_max,
                  int usb_timeout_ms)
{
  // Convert host timeout (ms) to device units (100 µs).
  // Per nfcpy in_comm_rf, the device expects (timeout_ms + 1) * 10.
  // 6552 is the largest input that keeps the result within uint16_t:
  // (6552 + 1) * 10 = 65530.  Larger values are clamped to 0xFFFF.
  uint16_t t;
  if (timeout_ms <= 0)
    t = 0xFFFF;
  else
    t = (uint16_t)(timeout_ms > 6552 ? 0xFFFF : (timeout_ms + 1) * 10);

  uint8_t cmd_buf[258];
  if (tx_len > 256) {
    pnd->last_error = NFC_EINVARG;
    return NFC_EINVARG;
  }
  cmd_buf[0] = (uint8_t)(t & 0xFF);
  cmd_buf[1] = (uint8_t)((t >> 8) & 0xFF);
  if (tx_len > 0)
    memcpy(cmd_buf + 2, tx, tx_len);

  uint8_t resp[RCS380_MAX_FRAME_LEN];
  int res = rcs380_cmd(pnd, RCS380_CMD_IN_COMM_RF,
                       cmd_buf, 2 + tx_len,
                       resp, sizeof(resp),
                       usb_timeout_ms > 0 ? usb_timeout_ms : RCS380_USB_IO_TIMEOUT);
  if (res < 0)
    return res;

  // STATUS is a 4-byte LE uint32.  Error responses (timeout, CRC, etc.) contain
  // only these 4 bytes with no metadata byte; success responses have a 5th metadata
  // byte followed by RF data.  Assemble from however many bytes arrived so that
  // every error flag path remains reachable.
  if (res < 1) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "InCommRF response too short (%d bytes)", res);
    pnd->last_error = NFC_EIO;
    return NFC_EIO;
  }

  uint32_t status = (uint32_t)resp[0]
                  | (res >= 2 ? (uint32_t)resp[1] << 8  : 0u)
                  | (res >= 3 ? (uint32_t)resp[2] << 16 : 0u)
                  | (res >= 4 ? (uint32_t)resp[3] << 24 : 0u);

  if (status != 0) {
    if (status & RCS380_ERR_TIMEOUT) {
      pnd->last_error = NFC_ETIMEOUT;
      return NFC_ETIMEOUT;
    }
    if (status & (RCS380_ERR_PROTOCOL | RCS380_ERR_PARITY | RCS380_ERR_CRC)) {
      pnd->last_error = NFC_ERFTRANS;
      return NFC_ERFTRANS;
    }
    if (status & RCS380_ERR_RF_OFF) {
      pnd->last_error = NFC_EIO;
      return NFC_EIO;
    }
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "InCommRF status error: %08" PRIx32, status);
    pnd->last_error = NFC_ECHIP;
    return NFC_ECHIP;
  }

  // Success: byte 4 is a metadata byte; byte 5+ is received RF data.
  if (res < 5) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "InCommRF success response too short (%d bytes)", res);
    pnd->last_error = NFC_EIO;
    return NFC_EIO;
  }

  // resp[4] is a metadata byte (received count etc.); skip it per nfcpy return data[5:]
  size_t rx_len = res > 5 ? (size_t)(res - 5) : 0;
  if (rx_len > rx_max) {
    pnd->last_error = NFC_EOVFLOW;
    return NFC_EOVFLOW;
  }
  if (rx && rx_len > 0)
    memcpy(rx, resp + 5, rx_len);

  return (int)rx_len;
}

// ISO14443A full anti-collision loop + optional RATS

static int
rcs380_activate_iso14443a(nfc_device *pnd, nfc_target *pnt)
{
  int res;
  nfc_iso14443a_info *nai = &pnt->nti.nai;
  memset(nai, 0, sizeof(*nai));

  // InSetRF must be called with RF off; subsequent InSetProtocol calls
  // (including those after REQA) may run with RF in any state.
  if ((res = rcs380_switch_rf(pnd, false)) < 0)
    return res;

  if ((res = rcs380_set_rf(pnd, 0x02, 0x03, 0x0F, 0x03)) < 0)
    return res;

  if ((res = rcs380_set_protocol(pnd, proto_106a_reqa,
                                 sizeof(proto_106a_reqa))) < 0)
    return res;

  // REQA (0x26, 7-bit last byte) → ATQA (2 bytes)
  static const uint8_t reqa[] = { 0x26 };
  uint8_t atqa[2];
  res = rcs380_in_comm_rf(pnd, 30, reqa, 1, atqa, sizeof(atqa), RCS380_USB_TIMEOUT);
  if (res < 0)
    return res;
  if (res != 2) {
    pnd->last_error = NFC_ERFTRANS;
    return NFC_ERFTRANS;
  }
  nai->abtAtqa[0] = atqa[0];
  nai->abtAtqa[1] = atqa[1];

  // Switch to parity-on SDD mode for anti-collision
  if ((res = rcs380_set_protocol(pnd, proto_106a_sdd, sizeof(proto_106a_sdd))) < 0)
    return res;

  static const uint8_t sel_codes[] = { 0x93, 0x95, 0x97 };
  uint8_t uid[10];
  size_t uid_len = 0;
  uint8_t sak = 0;

  for (int cascade = 0; cascade < 3; cascade++) {
    const uint8_t sdd_req[] = { sel_codes[cascade], 0x20 };
    uint8_t sdd_res[5];
    res = rcs380_in_comm_rf(pnd, 30, sdd_req, 2, sdd_res, sizeof(sdd_res),
                            RCS380_USB_TIMEOUT);
    if (res < 0)
      return res;
    if (res != 5) {
      pnd->last_error = NFC_ERFTRANS;
      return NFC_ERFTRANS;
    }

    // Verify BCC
    uint8_t bcc = sdd_res[0] ^ sdd_res[1] ^ sdd_res[2] ^ sdd_res[3];
    if (bcc != sdd_res[4]) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
              "%s", "BCC mismatch in SDD response");
      pnd->last_error = NFC_ERFTRANS;
      return NFC_ERFTRANS;
    }

    bool has_ct = (sdd_res[0] == ISO14443A_CT);
    if (has_ct) {
      if (uid_len + 3 > sizeof(uid)) {
        pnd->last_error = NFC_ERFTRANS;
        return NFC_ERFTRANS;
      }
      memcpy(uid + uid_len, sdd_res + 1, 3);
      uid_len += 3;
    } else {
      if (uid_len + 4 > sizeof(uid)) {
        pnd->last_error = NFC_ERFTRANS;
        return NFC_ERFTRANS;
      }
      memcpy(uid + uid_len, sdd_res, 4);
      uid_len += 4;
    }

    // Enable CRC for SELECT
    if ((res = rcs380_set_protocol(pnd, proto_106a_select,
                                   sizeof(proto_106a_select))) < 0)
      return res;

    uint8_t sel_req[7];
    sel_req[0] = sel_codes[cascade];
    sel_req[1] = 0x70;
    memcpy(sel_req + 2, sdd_res, 4);
    sel_req[6] = sdd_res[4];  // BCC

    uint8_t sak_buf[1];
    res = rcs380_in_comm_rf(pnd, 30, sel_req, sizeof(sel_req),
                            sak_buf, sizeof(sak_buf), RCS380_USB_TIMEOUT);
    if (res < 0)
      return res;
    if (res != 1) {
      pnd->last_error = NFC_ERFTRANS;
      return NFC_ERFTRANS;
    }
    sak = sak_buf[0];

    if (!(sak & 0x04))
      break;  // cascade bit clear: UID complete

    // Need another cascade level
    if ((res = rcs380_set_protocol(pnd, proto_106a_sdd,
                                   sizeof(proto_106a_sdd))) < 0)
      return res;
  }

  nai->btSak = sak;
  nai->szUidLen = uid_len;
  memcpy(nai->abtUid, uid, uid_len);

  if ((res = rcs380_set_protocol(pnd, proto_106a_data,
                                 sizeof(proto_106a_data))) < 0)
    return res;

  // RATS if ISO14443-4 compliant (SAK bit 5 set)
  if (sak & 0x20) {
    static const uint8_t rats[] = { 0xE0, 0x80 };  // FSDI=8 (256 bytes), CID=0
    uint8_t ats[256];
    res = rcs380_in_comm_rf(pnd, 200, rats, 2, ats, sizeof(ats),
                            RCS380_USB_IO_TIMEOUT);
    if (res > 0) {
      nai->szAtsLen = (size_t)res > sizeof(nai->abtAts) ? sizeof(nai->abtAts) : (size_t)res;
      memcpy(nai->abtAts, ats, nai->szAtsLen);
    }
    // Non-fatal if RATS fails
  }

  pnt->nm.nmt = NMT_ISO14443A;
  pnt->nm.nbr = NBR_106;
  return NFC_SUCCESS;
}

// FeliCa detection (SENSF_REQ / SENSF_RES)

static int
rcs380_activate_felica(nfc_device *pnd, nfc_target *pnt, nfc_baud_rate nbr)
{
  int res;
  nfc_felica_info *nfi = &pnt->nti.nfi;
  memset(nfi, 0, sizeof(*nfi));

  // InSetRF must be called with RF off; subsequent InSetProtocol calls may run with RF in any state.
  if ((res = rcs380_switch_rf(pnd, false)) < 0)
    return res;

  if (nbr == NBR_212)
    res = rcs380_set_rf(pnd, 0x01, 0x01, 0x0F, 0x01);
  else
    res = rcs380_set_rf(pnd, 0x01, 0x02, 0x0F, 0x02);
  if (res < 0)
    return res;

  if ((res = rcs380_set_protocol(pnd, proto_felica, sizeof(proto_felica))) < 0)
    return res;

  /*
   * NFC Port-100 SENSF_REQ data: [LEN][TSN][SC_H][SC_L][RC][RFU]
   * TSN=0x00 requests 1 time slot; command code 0x04 is added by the device
   * automatically and must NOT be included in the TX data (see nfcpy sense_ttf).
   * Using TSN=0x04 would request 16 slots and cause a timeout.
   */
  static const uint8_t sensf_req[] = { 0x06, 0x00, 0xFF, 0xFF, 0x01, 0x00 };
  uint8_t sensf_res[21];
  res = rcs380_in_comm_rf(pnd, 30, sensf_req, sizeof(sensf_req),
                          sensf_res, sizeof(sensf_res), RCS380_USB_TIMEOUT);
  if (res < 0)
    return res;
  if (res < 17) {
    pnd->last_error = NFC_ERFTRANS;
    return NFC_ERFTRANS;
  }

  // SENSF_RES: [LEN] [05] [IDm 8] [PMm 8] [RD 2 optional]
  nfi->szLen = (size_t)res;
  nfi->btResCode = sensf_res[1];
  memcpy(nfi->abtId,      sensf_res + 2,  8);  // IDm
  memcpy(nfi->abtPad,     sensf_res + 10, 8);  // PMm
  if (res >= 19)
    memcpy(nfi->abtSysCode, sensf_res + 18, 2);

  pnt->nm.nmt = NMT_FELICA;
  pnt->nm.nbr = nbr;
  return NFC_SUCCESS;
}

// ISO14443B detection (SENSB_REQ / SENSB_RES)

static int
rcs380_activate_iso14443b(nfc_device *pnd, nfc_target *pnt)
{
  int res;
  nfc_iso14443b_info *nbi = &pnt->nti.nbi;
  memset(nbi, 0, sizeof(*nbi));

  // InSetRF must be called with RF off; subsequent InSetProtocol calls may run with RF in any state.
  if ((res = rcs380_switch_rf(pnd, false)) < 0)
    return res;

  if ((res = rcs380_set_rf(pnd, 0x03, 0x07, 0x0F, 0x07)) < 0)
    return res;

  if ((res = rcs380_set_protocol(pnd, proto_106b, sizeof(proto_106b))) < 0)
    return res;

  // SENSB_REQ: AFI=0x00 (all), N=1 slot
  static const uint8_t sensb_req[] = { 0x05, 0x00, 0x08 };
  uint8_t sensb_res[15];
  res = rcs380_in_comm_rf(pnd, 30, sensb_req, sizeof(sensb_req),
                          sensb_res, sizeof(sensb_res), RCS380_USB_TIMEOUT);
  if (res < 0)
    return res;
  if (res < 12) {
    pnd->last_error = NFC_ERFTRANS;
    return NFC_ERFTRANS;
  }

  // SENSB_RES: [50] [PUPI 4] [APP_DATA 4] [PROTO_INFO 3]
  memcpy(nbi->abtPupi,            sensb_res + 1, 4);
  memcpy(nbi->abtApplicationData, sensb_res + 5, 4);
  memcpy(nbi->abtProtocolInfo,    sensb_res + 9, 3);

  pnt->nm.nmt = NMT_ISO14443B;
  pnt->nm.nbr = NBR_106;
  return NFC_SUCCESS;
}

// nfc_driver callbacks

static size_t
rcs380_scan(const nfc_context *context, nfc_connstring connstrings[],
            const size_t connstrings_len)
{
  (void)context;

  usb_prepare();

  size_t found = 0;

  for (struct usb_bus *bus = usb_get_busses(); bus; bus = bus->next) {
    for (struct usb_device *dev = bus->devices; dev; dev = dev->next) {
      if (dev->descriptor.idVendor  != RCS380_USB_VENDOR_ID  ||
          dev->descriptor.idProduct != RCS380_USB_PRODUCT_ID)
        continue;

      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
              "device found: Bus %s Device %s", bus->dirname, dev->filename);

      if (snprintf(connstrings[found], sizeof(nfc_connstring),
                   "%s:%s:%s", RCS380_DRIVER_NAME,
                   bus->dirname, dev->filename) >= (int)sizeof(nfc_connstring))
        continue;  // truncation, skip

      if (++found == connstrings_len)
        return found;
    }
  }
  return found;
}

static nfc_device *
rcs380_open(const nfc_context *context, const nfc_connstring connstring)
{
  char *dirname  = NULL;
  char *filename = NULL;
  int decode_level = connstring_decode(connstring, RCS380_DRIVER_NAME, "usb",
                                       &dirname, &filename);
  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
          "%d element(s) decoded from \"%s\"", decode_level, connstring);
  if (decode_level < 1) {
    free(dirname);
    free(filename);
    return NULL;
  }

  usb_prepare();

  nfc_device *pnd = NULL;
  usb_dev_handle *udh = NULL;

  for (struct usb_bus *bus = usb_get_busses(); bus; bus = bus->next) {
    if (decode_level > 1 && strcmp(bus->dirname, dirname) != 0)
      continue;

    for (struct usb_device *dev = bus->devices; dev; dev = dev->next) {
      if (dev->descriptor.idVendor  != RCS380_USB_VENDOR_ID  ||
          dev->descriptor.idProduct != RCS380_USB_PRODUCT_ID)
        continue;

      if (decode_level > 2 && strcmp(dev->filename, filename) != 0)
        continue;

      udh = usb_open(dev);
      if (!udh) {
        log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
                "%s", "usb_open failed");
        continue;
      }

      int res = usb_set_configuration(udh, 1);
      if (res < 0) {
        log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
                "Unable to set USB configuration (%s)", _usb_strerror(res));
        if (-res == EPERM)
          log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_INFO,
                  "Warning: Please double check USB permissions for device %04x:%04x",
                  RCS380_USB_VENDOR_ID, RCS380_USB_PRODUCT_ID);
        usb_close(udh);
        udh = NULL;
        continue;
      }

      res = usb_claim_interface(udh, 0);
      if (res < 0) {
        log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
                "Unable to claim USB interface (%s)", _usb_strerror(res));
        usb_close(udh);
        udh = NULL;
        continue;
      }

      break;  // device opened successfully
    }
    if (udh)
      break;
  }

  free(dirname);
  free(filename);

  if (!udh)
    return NULL;

  pnd = nfc_device_new(context, connstring);
  if (!pnd) {
    perror("malloc");
    usb_release_interface(udh, 0);
    usb_close(udh);
    return NULL;
  }

  snprintf(pnd->name, sizeof(pnd->name), "Sony / RC-S380 [PaSoRi]");
  pnd->driver           = &rcs380_driver;
  pnd->bCrc             = true;
  pnd->bPar             = true;
  pnd->bEasyFraming     = true;
  pnd->bInfiniteSelect  = false;
  pnd->bAutoIso14443_4  = false;

  pnd->driver_data = malloc(sizeof(struct rcs380_data));
  if (!pnd->driver_data) {
    perror("malloc");
    nfc_device_free(pnd);
    usb_release_interface(udh, 0);
    usb_close(udh);
    return NULL;
  }

  struct rcs380_data *data = DRIVER_DATA(pnd);
  data->udh = udh;
  atomic_store(&data->abort_flag, false);

  // Soft reset
  rcs380_send_ack(udh);

  // Drain any pending responses
  uint8_t tmp[RCS380_MAX_FRAME_LEN];
  while (rcs380_bulk_read(udh, tmp, sizeof(tmp), 10) > 0)
    ;

  /*
   * GetCommandType (0x28): query supported command type bitmask.
   * Returns 8-byte big-endian mask; bit N set means type N is supported.
   * NFC Port-100 type = 1; compatibility type = 0.
   */
  uint8_t type_mask[8] = { 0 };
  if (rcs380_cmd(pnd, RCS380_CMD_GET_CMD_TYPE,
                 NULL, 0,
                 type_mask, sizeof(type_mask), RCS380_USB_TIMEOUT) < 0) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "%s", "GetCommandType failed");
    goto error;
  }
  // Prefer type 1 (NFC Port-100); fall back to type 0
  uint8_t cmd_type = (type_mask[7] & 0x02) ? 1 : 0;

  // SetCommandType (0x2A): activate the chosen command type
  if (rcs380_simple_cmd(pnd, RCS380_CMD_SET_CMD_TYPE, &cmd_type, 1) < 0) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "%s", "SetCommandType failed");
    goto error;
  }

  // GetFirmwareVersion: update device name with firmware revision
  {
    uint8_t fw[16];
    int res = rcs380_cmd(pnd, RCS380_CMD_GET_FW_VER,
                         NULL, 0, fw, sizeof(fw), RCS380_USB_TIMEOUT);
    if (res >= 5 && fw[0] == 0x00) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
              "RC-S380 firmware: IC=%02X ROM=%02X FW=%02X.%02X",
              fw[1], fw[2], fw[3], fw[4]);
      snprintf(pnd->name, sizeof(pnd->name),
               "Sony / RC-S380 [PaSoRi] (FW %02X.%02X)", fw[3], fw[4]);
    }
  }

  // Leave RF off after init; initiator_init will turn it on
  rcs380_switch_rf(pnd, false);

  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
          "RC-S380 opened: %s", pnd->name);
  return pnd;

error:
  free(pnd->driver_data);
  pnd->driver_data = NULL;
  nfc_device_free(pnd);
  usb_release_interface(udh, 0);
  usb_close(udh);
  return NULL;
}

static void
rcs380_close(nfc_device *pnd)
{
  if (rcs380_switch_rf(pnd, false) < 0)
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "%s", "RF off failed during close");
  usb_release_interface(DRIVER_DATA(pnd)->udh, 0);
  usb_close(DRIVER_DATA(pnd)->udh);
  free(pnd->driver_data);
  pnd->driver_data = NULL;
  nfc_device_free(pnd);
}

static const char *
rcs380_strerror(const nfc_device *pnd)
{
  if (!pnd)
    return "rcs380: invalid device";
  switch (pnd->last_error) {
    case NFC_SUCCESS:      return "No error";
    case NFC_EIO:          return "I/O error";
    case NFC_EOVFLOW:      return "Buffer overflow";
    case NFC_ECHIP:        return "Chip error";
    case NFC_ETIMEOUT:     return "Timeout";
    case NFC_ERFTRANS:     return "RF transmission error";
    case NFC_EINVARG:      return "Invalid argument";
    case NFC_EOPABORTED:   return "Operation aborted";
    case NFC_EDEVNOTSUPP:  return "Operation not supported by device";
    case NFC_ESOFT:        return "Software error / out of memory";
    default:
      return "Unknown rcs380 driver error";
  }
}

static int
rcs380_initiator_init(nfc_device *pnd)
{
  return rcs380_switch_rf(pnd, true);
}

static int
rcs380_initiator_select_passive_target(nfc_device *pnd,
                                        const nfc_modulation nm,
                                        const uint8_t *pbtInitData,
                                        const size_t szInitData,
                                        nfc_target *pnt)
{
  // RC-S380 does not support filtered discovery (UID hint, ATR_REQ data, etc.).
  // pbtInitData / szInitData are silently ignored; any present tag is returned.
  (void)pbtInitData;
  (void)szInitData;

  int res;

  switch (nm.nmt) {
    case NMT_ISO14443A:
      if (nm.nbr != NBR_106) {
        pnd->last_error = NFC_EDEVNOTSUPP;
        return NFC_EDEVNOTSUPP;
      }
      res = rcs380_activate_iso14443a(pnd, pnt);
      break;

    case NMT_FELICA:
      if (nm.nbr != NBR_212 && nm.nbr != NBR_424) {
        pnd->last_error = NFC_EDEVNOTSUPP;
        return NFC_EDEVNOTSUPP;
      }
      res = rcs380_activate_felica(pnd, pnt, nm.nbr);
      break;

    case NMT_ISO14443B:
      if (nm.nbr != NBR_106) {
        pnd->last_error = NFC_EDEVNOTSUPP;
        return NFC_EDEVNOTSUPP;
      }
      res = rcs380_activate_iso14443b(pnd, pnt);
      break;

    default:
      pnd->last_error = NFC_EDEVNOTSUPP;
      return NFC_EDEVNOTSUPP;
  }

  if (res < 0)
    return res;

  return 1;  // 1 target found
}

static int
rcs380_initiator_deselect_target(nfc_device *pnd)
{
  int res = rcs380_switch_rf(pnd, false);
  if (res < 0)
    return res;
  return rcs380_switch_rf(pnd, true);
}

static int
rcs380_initiator_transceive_bytes(nfc_device *pnd,
                                   const uint8_t *pbtTx, const size_t szTx,
                                   uint8_t *pbtRx, const size_t szRx,
                                   int timeout)
{
  // Atomically test-and-clear the abort flag
  if (atomic_exchange(&DRIVER_DATA(pnd)->abort_flag, false)) {
    pnd->last_error = NFC_EOPABORTED;
    return NFC_EOPABORTED;
  }

  return rcs380_in_comm_rf(pnd, timeout, pbtTx, szTx, pbtRx, szRx,
                            timeout > 0 ? timeout + 1000 : RCS380_USB_IO_TIMEOUT);
}

static int
rcs380_initiator_target_is_present(nfc_device *pnd, const nfc_target *pnt)
{
  (void)pnt;
  // Zero-length InCommRF to check if tag is still present
  uint8_t rx[4];
  int res = rcs380_in_comm_rf(pnd, 30, NULL, 0, rx, sizeof(rx),
                              RCS380_USB_TIMEOUT);
  if (res < 0)
    return res;
  return NFC_SUCCESS;
}

static int
rcs380_device_set_property_bool(nfc_device *pnd, const nfc_property property,
                                 const bool bEnable)
{
  switch (property) {
    case NP_ACTIVATE_FIELD:
      return rcs380_switch_rf(pnd, bEnable);
    case NP_HANDLE_CRC:
      if (!bEnable) {
        pnd->last_error = NFC_EDEVNOTSUPP;
        return NFC_EDEVNOTSUPP;
      }
      pnd->bCrc = true;
      return NFC_SUCCESS;
    case NP_HANDLE_PARITY:
      if (!bEnable) {
        pnd->last_error = NFC_EDEVNOTSUPP;
        return NFC_EDEVNOTSUPP;
      }
      pnd->bPar = true;
      return NFC_SUCCESS;
    case NP_EASY_FRAMING:
      pnd->bEasyFraming = bEnable;
      return NFC_SUCCESS;
    case NP_INFINITE_SELECT:
      pnd->bInfiniteSelect = bEnable;
      return NFC_SUCCESS;
    case NP_AUTO_ISO14443_4:
      pnd->bAutoIso14443_4 = bEnable;
      return NFC_SUCCESS;
    case NP_ACCEPT_INVALID_FRAMES:
    case NP_ACCEPT_MULTIPLE_FRAMES:
    case NP_FORCE_ISO14443_A:
    case NP_FORCE_ISO14443_B:
    case NP_FORCE_SPEED_106:
      return NFC_SUCCESS;
    default:
      pnd->last_error = NFC_EDEVNOTSUPP;
      return NFC_EDEVNOTSUPP;
  }
}

static int
rcs380_device_set_property_int(nfc_device *pnd, const nfc_property property,
                                const int value)
{
  (void)value;
  switch (property) {
    case NP_TIMEOUT_COMMAND:
    case NP_TIMEOUT_ATR:
    case NP_TIMEOUT_COM:
      // Timeout values are not forwarded to the device; the driver uses
      // fixed defaults (RCS380_USB_TIMEOUT / RCS380_USB_IO_TIMEOUT).
      return NFC_SUCCESS;
    default:
      pnd->last_error = NFC_EDEVNOTSUPP;
      return NFC_EDEVNOTSUPP;
  }
}

static int
rcs380_get_supported_modulation(nfc_device *pnd, const nfc_mode mode,
                                 const nfc_modulation_type **const supported_mt)
{
  (void)pnd;
  if (mode == N_INITIATOR)
    *supported_mt = rcs380_initiator_modulations;
  else
    *supported_mt = rcs380_no_target_modulations;
  return NFC_SUCCESS;
}

static int
rcs380_get_supported_baud_rate(nfc_device *pnd, const nfc_mode mode,
                                const nfc_modulation_type nmt,
                                const nfc_baud_rate **const supported_br)
{
  (void)pnd;
  if (mode != N_INITIATOR) {
    *supported_br = NULL;
    return NFC_EDEVNOTSUPP;
  }
  switch (nmt) {
    case NMT_ISO14443A: *supported_br = rcs380_iso14443a_baud_rates; return NFC_SUCCESS;
    case NMT_FELICA:    *supported_br = rcs380_felica_baud_rates;    return NFC_SUCCESS;
    case NMT_ISO14443B: *supported_br = rcs380_iso14443b_baud_rates; return NFC_SUCCESS;
    default:
      *supported_br = NULL;
      return NFC_EDEVNOTSUPP;
  }
}

static int
rcs380_device_get_information_about(nfc_device *pnd, char **buf)
{
  *buf = malloc(512);
  if (!*buf) {
    pnd->last_error = NFC_ESOFT;
    return NFC_ESOFT;
  }
  snprintf(*buf, 512, "Driver: %s\nDevice: %s\n", RCS380_DRIVER_NAME, pnd->name);
  return NFC_SUCCESS;
}

static int
rcs380_abort_command(nfc_device *pnd)
{
  atomic_store(&DRIVER_DATA(pnd)->abort_flag, true);
  return NFC_SUCCESS;
}

static int
rcs380_idle(nfc_device *pnd)
{
  return rcs380_switch_rf(pnd, false);
}

const struct nfc_driver rcs380_driver = {
  .name                             = RCS380_DRIVER_NAME,
  .scan_type                        = NOT_INTRUSIVE,
  .scan                             = rcs380_scan,
  .open                             = rcs380_open,
  .close                            = rcs380_close,
  .strerror                         = rcs380_strerror,

  .initiator_init                   = rcs380_initiator_init,
  .initiator_init_secure_element    = NULL,
  .initiator_select_passive_target  = rcs380_initiator_select_passive_target,
  .initiator_poll_target            = NULL,
  .initiator_select_dep_target      = NULL,
  .initiator_deselect_target        = rcs380_initiator_deselect_target,
  .initiator_transceive_bytes       = rcs380_initiator_transceive_bytes,
  .initiator_transceive_bits        = NULL,
  .initiator_transceive_bytes_timed = NULL,
  .initiator_transceive_bits_timed  = NULL,
  .initiator_target_is_present      = rcs380_initiator_target_is_present,

  .target_init                      = NULL,  // RC-S380 does not support target mode
  .target_send_bytes                = NULL,
  .target_receive_bytes             = NULL,
  .target_send_bits                 = NULL,
  .target_receive_bits              = NULL,

  .device_set_property_bool         = rcs380_device_set_property_bool,
  .device_set_property_int          = rcs380_device_set_property_int,
  .get_supported_modulation         = rcs380_get_supported_modulation,
  .get_supported_baud_rate          = rcs380_get_supported_baud_rate,
  .device_get_information_about     = rcs380_device_get_information_about,

  .abort_command                    = rcs380_abort_command,
  .idle                             = rcs380_idle,
  .powerdown                        = NULL,
};
