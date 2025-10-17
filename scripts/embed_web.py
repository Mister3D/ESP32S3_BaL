Import("env")

import os
import base64
import gzip
from pathlib import Path

PROJECT_DIR = Path(env["PROJECT_DIR"])  # type: ignore
WEB_SRC_DIR = PROJECT_DIR / "lib" / "websrc"
OUTPUT_DIR = PROJECT_DIR / "include"
OUTPUT_HEADER = OUTPUT_DIR / "web_assets.h"

MIME_MAP = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".map": "application/json; charset=utf-8",
}


def iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def to_c_identifier(path: str) -> str:
    return (
        path.replace("/", "_")
        .replace("\\", "_")
        .replace(".", "_")
        .replace("-", "_")
    )


def compress_bytes(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=9)


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    assets = []
    if not WEB_SRC_DIR.exists():
        raise SystemExit(f"Missing web source directory: {WEB_SRC_DIR}")

    for f in iter_files(WEB_SRC_DIR):
        rel = f.relative_to(WEB_SRC_DIR).as_posix()
        url_path = "/" + rel  # e.g. /html/index.html
        raw = f.read_bytes()
        gz = compress_bytes(raw)
        ext = f.suffix.lower()
        mime = MIME_MAP.get(ext, "application/octet-stream")
        c_name = to_c_identifier(rel)
        assets.append({
            "rel": rel,
            "url": url_path,
            "c_name": c_name,
            "mime": mime,
            "gz": gz,
            "size": len(gz),
        })

    with OUTPUT_HEADER.open("w", encoding="utf-8") as fp:
        fp.write("#pragma once\n")
        fp.write("#include <stdint.h>\n\n")

        for a in assets:
            arr_name = f"web_{to_c_identifier(a['rel'])}_gz"
            fp.write(f"static const uint8_t {arr_name}[] = {{\n")
            line = []
            for i, b in enumerate(a["gz"]):
                line.append(f"0x{b:02x}")
                if len(line) == 16:
                    fp.write("    " + ", ".join(line) + ",\n")
                    line = []
            if line:
                fp.write("    " + ", ".join(line) + ",\n")
            fp.write("};\n\n")

        fp.write("typedef struct {\n")
        fp.write("    const char *url;\n")
        fp.write("    const char *mime;\n")
        fp.write("    const uint8_t *data;\n")
        fp.write("    const uint32_t size;\n")
        fp.write("} web_asset_t;\n\n")

        fp.write("static const web_asset_t WEB_ASSETS[] = {\n")
        for a in assets:
            arr_name = f"web_{to_c_identifier(a['rel'])}_gz"
            fp.write(
                f"    {{ \"{a['url']}\", \"{a['mime']}\", {arr_name}, {a['size']} }},\n"
            )
        fp.write("};\n\n")
        fp.write(f"static const uint32_t WEB_ASSETS_COUNT = {len(assets)};\n")

    print(f"Embedded {len(assets)} assets into {OUTPUT_HEADER}")


main()


