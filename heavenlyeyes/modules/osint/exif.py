"""Image EXIF Extractor — pull GPS, device, timestamps from images."""

import struct
import re
from pathlib import Path
from io import BytesIO
from heavenlyeyes.core.utils import (
    console, make_request, print_section, print_found, print_not_found,
    print_info, print_warning, print_error, create_table,
)

# ── EXIF Tag IDs ──────────────────────────────────────────────────────

EXIF_TAGS = {
    0x010F: "Camera Make",
    0x0110: "Camera Model",
    0x0112: "Orientation",
    0x011A: "X Resolution",
    0x011B: "Y Resolution",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSInfoIFDPointer",
    0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x920A: "FocalLength",
    0xA001: "ColorSpace",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber",
    0xA432: "LensSpecification",
    0xA433: "LensMake",
    0xA434: "LensModel",
}

GPS_TAGS = {
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x001D: "GPSDateStamp",
}


# ── Pure Python EXIF Parser ───────────────────────────────────────────

def _read_u16(data, offset, big_endian):
    fmt = ">H" if big_endian else "<H"
    return struct.unpack_from(fmt, data, offset)[0]


def _read_u32(data, offset, big_endian):
    fmt = ">I" if big_endian else "<I"
    return struct.unpack_from(fmt, data, offset)[0]


def _read_rational(data, offset, big_endian):
    fmt = ">II" if big_endian else "<II"
    num, den = struct.unpack_from(fmt, data, offset)
    return num / den if den != 0 else 0


def _read_srational(data, offset, big_endian):
    fmt = ">ii" if big_endian else "<ii"
    num, den = struct.unpack_from(fmt, data, offset)
    return num / den if den != 0 else 0


def _parse_ifd(data, offset, big_endian, tiff_start, tag_map):
    """Parse an IFD and return dict of {tag_name: value}."""
    results = {}
    try:
        count = _read_u16(data, offset, big_endian)
    except struct.error:
        return results

    for i in range(count):
        entry_offset = offset + 2 + i * 12
        try:
            tag = _read_u16(data, entry_offset, big_endian)
            type_id = _read_u16(data, entry_offset + 2, big_endian)
            num_values = _read_u32(data, entry_offset + 4, big_endian)
            value_offset_raw = data[entry_offset + 8:entry_offset + 12]
        except (struct.error, IndexError):
            continue

        tag_name = tag_map.get(tag, f"Tag_0x{tag:04X}")

        # Type sizes: 1=BYTE, 2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL, 7=UNDEFINED, 10=SRATIONAL
        type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 10: 8}
        type_size = type_sizes.get(type_id, 1)
        total_size = type_size * num_values

        if total_size <= 4:
            val_data_offset = entry_offset + 8
        else:
            val_data_offset = tiff_start + _read_u32(data, entry_offset + 8, big_endian)

        try:
            if type_id == 2:  # ASCII
                value = data[val_data_offset:val_data_offset + total_size].decode("ascii", errors="ignore").strip("\x00")
            elif type_id == 3:  # SHORT
                value = _read_u16(data, val_data_offset, big_endian)
            elif type_id == 4:  # LONG
                value = _read_u32(data, val_data_offset, big_endian)
            elif type_id == 5:  # RATIONAL
                if num_values == 1:
                    value = _read_rational(data, val_data_offset, big_endian)
                else:
                    value = [_read_rational(data, val_data_offset + j * 8, big_endian) for j in range(num_values)]
            elif type_id == 10:  # SRATIONAL
                value = _read_srational(data, val_data_offset, big_endian)
            else:
                value = data[val_data_offset:val_data_offset + min(total_size, 64)]
                if isinstance(value, bytes):
                    try:
                        value = value.decode("ascii", errors="ignore")
                    except Exception:
                        value = value.hex()
        except (struct.error, IndexError):
            continue

        results[tag_name] = value

    return results


def _parse_exif(data: bytes) -> dict:
    """Parse EXIF data from JPEG bytes."""
    result = {"main": {}, "gps": {}, "exif_sub": {}}

    # Find EXIF marker (APP1: FF E1)
    idx = data.find(b"\xFF\xE1")
    if idx == -1:
        return result

    # Skip marker + length
    app1_length = struct.unpack_from(">H", data, idx + 2)[0]
    exif_start = idx + 4

    # Check "Exif\x00\x00"
    if data[exif_start:exif_start + 6] != b"Exif\x00\x00":
        return result

    tiff_start = exif_start + 6

    # Byte order
    byte_order = data[tiff_start:tiff_start + 2]
    big_endian = byte_order == b"MM"

    # Verify TIFF magic (42)
    magic = _read_u16(data, tiff_start + 2, big_endian)
    if magic != 42:
        return result

    # IFD0 offset
    ifd0_offset = _read_u32(data, tiff_start + 4, big_endian)
    ifd0_abs = tiff_start + ifd0_offset

    # Parse main IFD
    main_tags = _parse_ifd(data, ifd0_abs, big_endian, tiff_start, EXIF_TAGS)
    result["main"] = {k: v for k, v in main_tags.items() if not k.endswith("Pointer")}

    # Parse EXIF sub-IFD if pointer exists
    exif_ptr = main_tags.get("ExifIFDPointer")
    if isinstance(exif_ptr, int):
        sub_tags = _parse_ifd(data, tiff_start + exif_ptr, big_endian, tiff_start, EXIF_TAGS)
        result["exif_sub"] = {k: v for k, v in sub_tags.items() if not k.endswith("Pointer")}

    # Parse GPS IFD if pointer exists
    gps_ptr = main_tags.get("GPSInfoIFDPointer")
    if isinstance(gps_ptr, int):
        gps_tags = _parse_ifd(data, tiff_start + gps_ptr, big_endian, tiff_start, GPS_TAGS)
        result["gps"] = gps_tags

    return result


def _gps_to_decimal(gps_data: dict) -> dict | None:
    """Convert GPS EXIF data to decimal lat/lon."""
    lat = gps_data.get("GPSLatitude")
    lat_ref = gps_data.get("GPSLatitudeRef", "N")
    lon = gps_data.get("GPSLongitude")
    lon_ref = gps_data.get("GPSLongitudeRef", "E")

    if not lat or not lon:
        return None

    if isinstance(lat, list) and len(lat) == 3:
        lat_dec = lat[0] + lat[1] / 60 + lat[2] / 3600
    elif isinstance(lat, (int, float)):
        lat_dec = float(lat)
    else:
        return None

    if isinstance(lon, list) and len(lon) == 3:
        lon_dec = lon[0] + lon[1] / 60 + lon[2] / 3600
    elif isinstance(lon, (int, float)):
        lon_dec = float(lon)
    else:
        return None

    if lat_ref == "S":
        lat_dec = -lat_dec
    if lon_ref == "W":
        lon_dec = -lon_dec

    return {
        "latitude": round(lat_dec, 6),
        "longitude": round(lon_dec, 6),
        "google_maps": f"https://www.google.com/maps?q={lat_dec},{lon_dec}",
    }


# ── Image Fetching ────────────────────────────────────────────────────

def _fetch_image(source: str) -> bytes | None:
    """Fetch image from URL or read from local path."""
    if source.startswith("http://") or source.startswith("https://"):
        resp = make_request(source, timeout=15)
        if resp and resp.status_code == 200:
            return resp.content
        return None
    else:
        path = Path(source)
        if path.exists() and path.is_file():
            return path.read_bytes()
        return None


# ════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ════════════════════════════════════════════════════════════════════════

def extract_exif(source: str) -> dict:
    """Extract EXIF data from an image (URL or local path)."""
    print_section("Image EXIF Extraction")
    results = {"source": source, "metadata": {}, "gps": None, "security_findings": []}

    # ── Fetch image ──
    console.print(f"[bold]Source:[/bold] {source}\n")
    console.print("  [dim]Fetching image...[/dim]")

    image_data = _fetch_image(source)
    if not image_data:
        print_error("Could not fetch or read image")
        return results

    print_found("Image Size", f"{len(image_data):,} bytes")

    # Detect format
    if image_data[:2] == b"\xFF\xD8":
        fmt = "JPEG"
    elif image_data[:8] == b"\x89PNG\r\n\x1a\n":
        fmt = "PNG"
        print_warning("PNG files typically don't contain EXIF data")
    elif image_data[:4] in (b"RIFF", b"WEBP"):
        fmt = "WebP"
    else:
        fmt = "Unknown"
    print_found("Format", fmt)

    # ── Parse EXIF ──
    console.print("\n[bold]Parsing EXIF data...[/bold]\n")
    exif = _parse_exif(image_data)

    all_tags = {}
    all_tags.update(exif.get("main", {}))
    all_tags.update(exif.get("exif_sub", {}))

    if not all_tags and not exif.get("gps"):
        print_warning("No EXIF metadata found (may have been stripped)")
        results["metadata"]["stripped"] = True
        return results

    # ── Display metadata ──
    table = create_table("EXIF Metadata", [("Tag", "cyan"), ("Value", "white")])

    security_tags = ["Camera Make", "Camera Model", "Software", "Artist",
                     "Copyright", "CameraOwnerName", "BodySerialNumber",
                     "DateTimeOriginal", "DateTime"]

    for tag, value in all_tags.items():
        display_val = str(value)
        if len(display_val) > 80:
            display_val = display_val[:77] + "..."
        table.add_row(tag, display_val)
        results["metadata"][tag] = value

        # Flag security-relevant data
        if tag in security_tags and value:
            results["security_findings"].append({
                "tag": tag,
                "value": str(value),
                "risk": "PII exposure" if tag in ("Artist", "CameraOwnerName", "Copyright") else "Device fingerprinting",
            })

    console.print(table)

    # ── GPS data ──
    if exif.get("gps"):
        console.print("\n[bold red]GPS DATA FOUND[/bold red]\n")
        gps_decimal = _gps_to_decimal(exif["gps"])

        if gps_decimal:
            results["gps"] = gps_decimal
            print_found("Latitude", str(gps_decimal["latitude"]))
            print_found("Longitude", str(gps_decimal["longitude"]))
            print_found("Google Maps", gps_decimal["google_maps"])
            results["security_findings"].append({
                "tag": "GPS Coordinates",
                "value": f"{gps_decimal['latitude']}, {gps_decimal['longitude']}",
                "risk": "Exact physical location exposed",
            })
        else:
            # Show raw GPS tags
            for tag, val in exif["gps"].items():
                print_found(tag, str(val))
    else:
        print_info("No GPS data found")

    # ── Security Summary ──
    if results["security_findings"]:
        console.print("\n[bold yellow]Security Findings[/bold yellow]\n")
        sec_table = create_table("Privacy Risks", [
            ("Data", "yellow"),
            ("Value", "white"),
            ("Risk", "red"),
        ])
        for finding in results["security_findings"]:
            sec_table.add_row(finding["tag"], finding["value"][:50], finding["risk"])
        console.print(sec_table)

    # ── Summary ──
    total_tags = len(all_tags)
    has_gps = "Yes" if results["gps"] else "No"
    risks = len(results["security_findings"])
    console.print(f"\n[bold green]EXIF extraction complete — {total_tags} tags, GPS: {has_gps}, {risks} privacy risks[/bold green]")

    return results


def batch_exif(urls: list[str]) -> list[dict]:
    """Extract EXIF from multiple images."""
    print_section("Batch EXIF Extraction")
    results = []
    for i, url in enumerate(urls, 1):
        console.print(f"\n[bold cyan]Image {i}/{len(urls)}[/bold cyan]")
        results.append(extract_exif(url))
    return results
