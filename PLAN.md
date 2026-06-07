# Bad Image Corpus Generator — Plan

## Goal
Zero-dependency Python script (`generate_bad_corpus.py`) that generates a corpus of badly structured images (JPEG, PNG, GIF, WebP, AVIF, JP2/JPEG 2000) targeting real CVEs in image parsing libraries.

## Constraints
- Python stdlib only: `os`, `struct`, `zlib`, `argparse`, `random`
- Seeded RNG (`--seed 42`) for deterministic, reproducible output
- Each generator method documents which CVE or corruption scenario it tests
- Output filenames include CVE numbers where applicable

## CLI
```
python generate_bad_corpus.py --out corpus/ --seed 42 --formats jpeg,png,gif,webp,avif,jp2
```

## Output Layout
```
corpus/
├── jpeg/    000-empty.jpg … 030-put-pixels-oob-cve-2018-19664.jpg
├── png/     000-empty.png … 025-optipng-reduce-uaf-cve-2012-4432.png
├── gif/     000-empty.gif … 018-gifsicle-double-free-cve-2017-18120.gif
├── webp/    000-empty.webp … 011-iccp-bad-profile.webp
├── avif/    000-empty.avif … 009-grid-tile-oob-cve-2026-32740.avif
├── jp2/     000-empty.jp2 … 018-sycc420-to-rgb-oob-cve-2021-3575.jp2
└── confusion/   *.{jpg,png,gif,webp,avif,jp2} (format-mismatched extensions)
```

## Generator Breakdown

### JPEG — 31 methods

| # | Method | CVE / Scenario |
|---|--------|---------------|
| 0 | empty | SOI + EOI only |
| 1 | truncated | SOI only |
| 2 | garbage-only | CVE-2021-22543 — OOB read on garbage data |
| 3 | garbage-prefix | CVE-2019-13960 — OOB with garbage prefix |
| 4 | garbage-suffix | stray data after EOI |
| 5 | double-soi | nested SOI markers |
| 6 | bad-dimensions | SOF0 with 0×0 |
| 7 | huge-dimensions | CVE-2021-3456 — heap OOB via 65535×65535 |
| 8 | corrupted-scan | CVE-2019-2201 — heap OOB via corrupt scan |
| 9 | dht-without-dqt | CVE-2021-46829 — heap OOB on missing DQT |
| 10 | dqt-12-bit | CVE-2023-2804 — 12-bit lossless JPEG OOB |
| 11 | missing-sos | no SOS marker at all |
| 12 | sos-before-sof | SOS appears before SOF0 |
| 13 | malformed-sos | wrong component count in SOS header |
| 14 | dnl-marker | DNL marker changes dimensions mid-stream |
| 15 | dri-zero | CVE-2020-13790 — infinite loop via DRI=0 |
| 16 | oversized-scan-length | declared scan longer than actual data |
| 17 | marker-after-eoi | extraneous marker after EOI |
| 18 | transform-oob | CVE-2020-17541 — stack buffer overflow via lossless transform (libjpeg-turbo) |
| 19 | smooth-oob-read | CVE-2021-29390 — heap OOB read in decompress_smooth_data (libjpeg-turbo) |
| 20 | jpegoptim-optimize-oob | CVE-2023-27781 — heap overflow in optimize() (jpegoptim) |
| 21 | jpegoptim-segfault | CVE-2022-32325 — segfault via READ on zero-height (jpegoptim) |
| 22 | libjpeg62-eof-loop | CVE-2018-11813 — EOF handling large loop (libjpeg62) |
| 23 | rust-jpeg-sos-oob | CVE-2020-25019 — SOS component mismatch OOB (rust-jpeg-decoder) |
| 24 | nvjpeg-oob-dims | CVE-2025-23274 — OOB via extreme dims + multiple scans (nvjpeg) |
| 25 | duplicate-dht-null-deref | CVE-2017-15232 — NULL deref via duplicate DHT (libjpeg-turbo) |
| 26 | get-sos-oob | CVE-2012-2806 — heap overflow in get_sos (libjpeg-turbo) |
| 27 | duplicate-sos-uninit | CVE-2013-6629 — uninit memory via duplicate SOS (libjpeg) |
| 28 | bad-exif-marker | CVE-2014-9092 — crash via malformed Exif marker (libjpeg-turbo) |
| 29 | jpegoptim-double-free | CVE-2018-11416 — double-free via realloc (jpegoptim) |
| 30 | put-pixels-oob | CVE-2018-19664 — heap OOB read in put_pixel_rows (libjpeg-turbo) |

### PNG — 26 methods

| # | Method | CVE / Scenario |
|---|--------|---------------|
| 0 | empty | minimal valid PNG |
| 1 | truncated | signature only |
| 2 | signature-only | sig + IHDR, no IEND |
| 3 | bad-ihdr-crc | corrupted IHDR CRC |
| 4 | zero-dimensions | IHDR with 0×0 |
| 5 | huge-dimensions | IHDR with 0x7FFFFFFF |
| 6 | garbage-appended | valid PNG + garbage suffix |
| 7 | garbage-prepended | garbage + valid PNG |
| 8 | wrong-chunk-type | invalid chunk type "fAkE" |
| 9 | no-ihdr | first chunk is IDAT |
| 10 | duplicate-ihdr | two IHDR chunks |
| 11 | negative-dimensions | CVE-2020-27814 — int32 overflow in dimensions |
| 12 | oversized-chunk-length | CVE-2021-20254 — integer overflow in chunk length |
| 13 | idat-with-garbage | valid structure, garbage zlib stream |
| 14 | plte-after-idat | PLTE chunk after IDAT (wrong order) |
| 15 | multiple-iend | two IEND chunks |
| 16 | missing-iend | file ends without IEND |
| 17 | chrm-bad-length | cHRM with incorrect chunk length |
| 18 | ztxt-null-keyword | zTXt with null byte in keyword |
| 19 | phys-zero-dpi | CVE-2022-30699 — div-by-zero via pHYs zero DPI |
| 20 | splt-double-free | CVE-2015-7700 — double-free via sPLT chunk (pngcrush) |
| 21 | pngcrush-unusual-chunks | CVE-2019-12971 — segfault via unusual chunk ordering (pngcrush) |
| 22 | pngquant-integer-overflow | CVE-2016-5735 — integer overflow via stride (pngquant) |
| 23 | optipng-heap-oob | CVE-2017-16938 — heap OOB via up-filter IDAT (optipng) |
| 24 | optipng-use-after-free | CVE-2015-7801 — use-after-free via oFFs+pHYs (optipng) |
| 25 | optipng-reduce-uaf | CVE-2012-4432 — UAF in opngreduc.c via tRNS+palette (optipng) |

### GIF — 19 methods

| # | Method | CVE / Scenario |
|---|--------|---------------|
| 0 | empty | header + LSD + trailer |
| 1 | truncated | header only |
| 2 | garbage-only | random bytes |
| 3 | bad-header | wrong magic "GIF99b" |
| 4 | zero-dimensions | LSD with 0×0 |
| 5 | huge-dimensions | LSD with 65535×65535 |
| 6 | missing-color-table | CVE-2020-19247 — GCT flag set but no table |
| 7 | bad-extension-length | extension block with wrong size |
| 8 | bad-gce-disposal | GCE with invalid disposal method |
| 9 | bad-app-extension | application extension with bad data |
| 10 | image-without-descriptor | image sub-block without image descriptor |
| 11 | lzw-large-min-code | CVE-2023-43913 — LZW min code size = 15 |
| 12 | gifsicle-null-deref | CVE-2020-19752 — NULL deref in find_color_or_error (gifsicle) |
| 13 | gifsicle-fpe | CVE-2023-46009 — FPE in resize_stream (gifsicle) |
| 14 | gifsicle-heap-oob | CVE-2023-36193 — heap buffer overflow (gifsicle) |
| 15 | giftrans-stack-oob | CVE-2021-45972 — stack buffer overflow (giftrans) |
| 16 | rust-gif-oob-read | CVE-2019-20922 — OOB read in frame data (rust-gif) |
| 17 | gifsicle-uaf | CVE-2017-1000421 — UAF in read_gif via extension blocks (gifsicle) |
| 18 | gifsicle-double-free | CVE-2017-18120 — double-free in read_gif (gifsicle) |

### WebP — 12 methods

| # | Method | CVE / Scenario |
|---|--------|---------------|
| 0 | empty | RIFF header only |
| 1 | truncated | partial RIFF header |
| 2 | garbage-only | random bytes |
| 3 | bad-riff-size | RIFF size ≠ file size − 8 |
| 4 | bad-fourcc | chunk tag "xV P" |
| 5 | vp8-bad-dims | CVE-2023-4863 — VP8 keyframe with corrupt dimensions |
| 6 | vp8l-bad-huffman | CVE-2023-4863 — VP8L with bad huffman table |
| 7 | vp8x-bad-flags | VP8X with reserved flags set |
| 8 | anim-bad-timing | ANIM/ANMF with zero frame duration |
| 9 | alph-wrong-size | ALPH chunk size ≠ expected |
| 10 | lossy-corrupt-partition | VP8 with corrupt partition data |
| 11 | iccp-bad-profile | ICCP with truncated profile |

### AVIF — 10 methods

| # | Method | CVE / Scenario |
|---|--------|---------------|
| 0 | empty | ftyp box only |
| 1 | truncated | partial ftyp |
| 2 | garbage-only | random bytes |
| 3 | bad-ftyp-brand | ftyp major brand = "xxxx" |
| 4 | missing-mdat | no mdat box |
| 5 | zero-dimensions | av1C with 0×0 dimensions |
| 6 | huge-dimensions | av1C with 65535×65535 |
| 7 | wrong-profile | av1C with invalid profile byte |
| 8 | truncated-av1-obu | mdat with truncated AV1 OBU data |
| 9 | grid-tile-oob | CVE-2026-32740 — grid tile out-of-bounds property index |

### JP2 / JPEG 2000 — 19 methods

| # | Method | CVE / Scenario |
|---|--------|---------------|
| 0 | empty | minimal valid JP2 (sig + ftyp + jp2h + jp2c) |
| 1 | truncated | partial signature box |
| 2 | garbage-only | random bytes |
| 3 | bad-sig | wrong signature box content |
| 4 | bad-ftyp | ftyp with wrong major brand |
| 5 | zero-dimensions | SIZ marker with 0×0 |
| 6 | huge-dimensions | SIZ marker with 65535×65535 |
| 7 | missing-codestream | no jp2c box |
| 8 | truncated-codestream | SOC marker only |
| 9 | bad-siz-rsiz | SIZ with invalid Rsiz |
| 10 | qcd-missing | codestream without QCD marker |
| 11 | corrupted-packet | SOD followed by garbage data |
| 12 | openjpeg-oob-siz | CVE-2025-54874 — OOB heap write via undersized stream (openjpeg) |
| 13 | plte-missing-colr | CVE-2016-7445 — NULL deref via missing colr (openjpeg) |
| 14 | icc-bad-profile | CVE-2013-4289 — integer overflow via oversized ICC (openjpeg) |
| 15 | tile-size-oob | CVE-2016-5152 — integer overflow → heap OOB in tile size (openjpeg) |
| 16 | dwt-interleave-oob | CVE-2016-5157 — heap OOB in opj_dwt_interleave_v (openjpeg) |
| 17 | mcc-oob-write | CVE-2016-8332 — OOB heap write via malformed mcc records (openjpeg) |
| 18 | sycc420-to-rgb-oob | CVE-2021-3575 — heap OOB in sycc420_to_rgb (openjpeg) |

### Format Confusion — 8 files
Cross-format extension mismatches (e.g. `.jpg` with PNG magic, `.png` with JPEG magic).

## Key Implementation Details

- PNG CRCs via `zlib.crc32`
- PNG IDAT compression via `zlib.compress`
- VP8/VP8L headers constructed programmatically with proper bit-level encoding
- AV1 OBU bitstream built with MSB-first bit writer (Sequence Header + Frame OBU)
- GIF LZW data uses minimum code size byte + garbage sub-blocks
- AVIF and JP2 box structures built from scratch using shared `_box` / `_full_box` helpers
- JP2 codestream uses raw JPEG 2000 markers (SOC, SIZ, COD, QCD, SOT, SOD, EOC)
- Seeded `random.Random` instance — NOT `random.seed()` — for generator isolation
