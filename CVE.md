# CVE Coverage

This corpus generates 117 image files targeting 48 unique CVEs across 13 image-processing libraries. Each file exercises a specific corruption scenario that triggers a known vulnerability.

| CVE                 | Format   | Library            | Description                                                                       |
|---------------------|----------|--------------------|-----------------------------------------------------------------------------------|
| CVE-2026-32740      | AVIF     | libavif/libheif    | AVIF grid tile OOB property index in ipma box                                     |
| CVE-2017-1000421    | GIF      | gifsicle           | Use-after-free in `read_gif` via extension blocks                                 |
| CVE-2017-18120      | GIF      | gifsicle           | Double-free in `read_gif` via multiple image descriptors                          |
| CVE-2019-20922      | GIF      | rust-gif           | OOB read via insufficient bounds checking in frame data                           |
| CVE-2020-19247      | GIF      | giflib             | Heap OOB via GCT flag set but no global color table data                          |
| CVE-2020-19752      | GIF      | gifsicle           | NULL pointer dereference in `find_color_or_error()` via crafted color table       |
| CVE-2021-45972      | GIF      | giftrans           | Stack buffer overflow via crafted GIF color table size in extension data          |
| CVE-2023-36193      | GIF      | gifsicle           | Heap buffer overflow via oversized image dimensions in descriptor                 |
| CVE-2023-43913      | GIF      | giflib             | OOB read via LZW minimum code size set to 15                                      |
| CVE-2023-46009      | GIF      | gifsicle           | Floating point exception in `resize_stream()` via extreme resize ratio            |
| CVE-2013-4289       | JP2      | openjpeg           | Integer overflow via oversized ICC profile in Color Specification box             |
| CVE-2016-5152       | JP2      | openjpeg           | Integer overflow → heap-buffer-overflow in `opj_tcd_get_decoded_tile_size`        |
| CVE-2016-5157       | JP2      | openjpeg           | Heap-buffer-overflow in `opj_dwt_interleave_v` via extreme decomposition level    |
| CVE-2016-7445       | JP2      | openjpeg           | NULL pointer dereference via missing Color Specification box with palette         |
| CVE-2016-8332       | JP2      | openjpeg           | OOB heap write via malformed mcc (multiple component transformation) records      |
| CVE-2021-3575       | JP2      | openjpeg           | Heap-buffer-overflow in `sycc420_to_rgb` via extreme chroma-subsampled dimensions |
| CVE-2025-54874      | JP2      | openjpeg           | OOB heap write via undersized data stream in `opj_jp2_read_header()`              |
| CVE-2012-2806       | JPEG     | libjpeg-turbo      | Heap overflow in `get_sos()` via SOS with out-of-range spectral parameters        |
| CVE-2013-6629       | JPEG     | libjpeg-turbo      | Uninitialized memory disclosure via duplicate SOS markers                         |
| CVE-2014-9092       | JPEG     | libjpeg-turbo      | Crash via malformed Exif (APP1) marker with corrupt TIFF header                   |
| CVE-2017-15232      | JPEG     | libjpeg-turbo      | NULL pointer dereference in `jdmarker.c` via duplicate DHT marker                 |
| CVE-2018-11416      | JPEG     | jpegoptim          | Double-free via invalid realloc in malformed progressive scan                     |
| CVE-2018-11813      | JPEG     | libjpeg62          | Excessive CPU loop via improper EOF handling in truncated scan                    |
| CVE-2018-19664      | JPEG     | libjpeg-turbo      | Heap OOB read in `put_pixel_rows()` for 256-color output                          |
| CVE-2019-13960      | JPEG     | libjpeg-turbo      | OOB read via garbage data prefixed before SOI marker                              |
| CVE-2019-2201       | JPEG     | libjpeg-turbo      | Heap OOB via corrupt scan data with valid marker structure                        |
| CVE-2020-13790      | JPEG     | libjpeg-turbo      | Infinite loop via DRI (Define Restart Interval) set to zero                       |
| CVE-2020-17541      | JPEG     | libjpeg-turbo      | Stack buffer overflow via malformed lossless transform marker                     |
| CVE-2020-25019      | JPEG     | rust-jpeg-decoder  | OOB read via SOS component count mismatch vs SOF declaration                      |
| CVE-2021-22543      | JPEG     | libjpeg-turbo      | OOB read on pure garbage data (no valid markers)                                  |
| CVE-2021-29390      | JPEG     | libjpeg-turbo      | Heap OOB read (2 bytes) in `decompress_smooth_data()`                             |
| CVE-2021-3456       | JPEG     | libjpeg-turbo      | Heap OOB via 65535×65535 dimensions                                               |
| CVE-2021-46829      | JPEG     | libjpeg-turbo      | Heap buffer over-read — DHT present but DQT missing                               |
| CVE-2022-32325      | JPEG     | jpegoptim          | Segfault via READ memory access on zero-height progressive JPEG                   |
| CVE-2023-27781      | JPEG     | jpegoptim          | Heap overflow in `optimize()` via oversized Huffman table                         |
| CVE-2023-2804       | JPEG     | libjpeg-turbo      | 12-bit lossless JPEG OOB via precision=1 DQT                                      |
| CVE-2025-23274      | JPEG     | nvjpeg             | OOB via extreme dimensions and multiple scans (integer overflow)                  |
| CVE-2025-23275      | JPEG     | nvjpeg             | GPU-side OOB write via image dimensions violating internal bounds                 |
| CVE-2012-4432       | PNG      | optipng            | Use-after-free in `opngreduc.c` via tRNS chunk with indexed color palette         |
| CVE-2015-7700       | PNG      | pngcrush           | Double-free via crafted sPLT chunk with zero palette entries                      |
| CVE-2015-7801       | PNG      | optipng            | Use-after-free via oFFs chunk followed by pHYs                                    |
| CVE-2016-5735       | PNG      | pngquant           | Integer overflow in `rwpng_read_image24_libpng()` via IHDR stride                 |
| CVE-2017-16938      | PNG      | optipng            | Heap buffer overflow via up-filter IDAT rows                                      |
| CVE-2019-12971      | PNG      | pngcrush           | Segfault via unusual chunk ordering (private chunks interleaved)                  |
| CVE-2020-27814      | PNG      | libpng             | Heap buffer overflow via int32 overflow in negative dimensions                    |
| CVE-2021-20254      | PNG      | libpng             | Integer overflow via chunk length set to 0xFFFFFFFF                               |
| CVE-2022-30699      | PNG      | libpng             | Division by zero via pHYs chunk with zero dots-per-unit                           |
| CVE-2023-4863       | WebP     | libwebp            | Heap buffer overflow via VP8 keyframe / VP8L bad huffman table                    |
