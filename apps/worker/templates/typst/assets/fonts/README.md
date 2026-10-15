The unmodified Noto Sans CJK Regular and Bold collections (Sans 2.004) are
bundled here so report rendering works without host or image system fonts.
Both proportional and monospace Chinese faces are included. See OFL.txt.

Upstream: https://github.com/notofonts/noto-cjk (Sans/OTC, Sans2.004)
Source distribution: Debian fonts-noto-cjk 1:20220127+repack1-1.

SHA-256:

    b76b0433203017ca80401b2ee0dd69350349871c4b19d504c34dbdd80541690a  NotoSansCJK-Regular.ttc
    faa5f3656a78b2e2d450d27fe8382c778bc2b6bb5ea29c986664a6a435056ceb  NotoSansCJK-Bold.ttc

The worker Docker build copies this directory with the report template. The
renderer passes it to Typst via --font-path and disables system font discovery;
Typst's embedded Latin fonts remain available. If font files change, their bytes
invalidate persisted PDF provenance along with changes to report.typ.
