# Bad Images

Image files, mostly badly structured, for testing code that validates image integrity.
The corpus targets 48 CVEs across 13 image-processing libraries.

## Sourced from

* https://upload.wikimedia.org/wikipedia/commons/7/7b/Alyah_1948-2007_ru.png
* https://upload.wikimedia.org/wikipedia/commons/2/28/Gnumeric_tutorial_for_chemists_Inkscape-fr.png
* https://commons.wikimedia.org/wiki/File:JPEG_example_flower.jpg

## Generated corpus

```sh
python3 generate_bad_corpus.py --out corpus/ --seed 42
```

Generates **125 files** (117 corpus + 8 format-confusion) targeting CVEs in:

| Format   | Libraries                                                              |
|----------|------------------------------------------------------------------------|
| JPEG     | libjpeg-turbo, jpegoptim, libjpeg62, rust-jpeg-decoder, nvjpeg         |
| PNG      | libpng, optipng, pngcrush, pngquant                                    |
| GIF      | giflib, gifsicle, giftrans, rust-gif                                   |
| WebP     | libwebp                                                                |
| AVIF     | libavif/libheif                                                        |
| JP2      | openjpeg                                                               |

### Output layout

```
corpus/
├── avif/
├── confusion/
├── gif/
├── jp2/
├── jpeg/
├── png/
└── webp/
```

## CVE reference

See `CVE.md` for the full table of all covered vulnerabilities.
