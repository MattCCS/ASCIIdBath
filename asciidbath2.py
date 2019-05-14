# encoding: utf-8

"""
A best-effort viewer for every unicode codepoint -- in every encoding -- ever.
"""

import argparse
import sys


if not (len('Ø') == 1 and ord('Ø') == 216):
    exit("ENCODING ERROR: Please interpret this file as UTF-8 encoded text.\n"
         "This may require changing the first line of this file to read:\n"
         "# encoding: utf-8")

ANSI_DEBUG = True

ANSI_NORMAL = '\x1b[0m'
ANSI_BOLD = '\x1b[1m'

ANSI_RED = '\x1b[31m'
ANSI_GREEN = '\x1b[32m'
ANSI_BLUE = '\x1b[34m'


ENCODINGS = [
    'ascii',
    'cp1252',
    'latin1',
    'koi8_r',
    'utf-8',
    'utf-16',
    'utf-32',
]


# http://www.amp-what.com/unicode/search/control%20pictures
CONTROLS = {
    0x0000: 0x2400,  # NUL/null
    0x0001: 0x2401,  # SOH/start of heading
    0x0002: 0x2402,  # STX/start of text
    0x0003: 0x2403,  # ETX/end of text
    0x0004: 0x2404,  # EOT/end of transmission
    0x0005: 0x2405,  # ENQ/enquiry
    0x0006: 0x2406,  # ACK/acknowledge
    0x0007: 0x2407,  # BEL/bell
    0x0008: 0x2408,  # BS/backspace
    0x0009: 0x2409,  # HT/horizontal tabulation
    0x000a: 0x2424,  # NL/newline -- or 0x240a/LF/line feed
    0x000b: 0x240b,  # VT/vertical tab
    0x000c: 0x240c,  # FF/form feed -- or NP/new page
    0x000d: 0x240d,  # CR/carriage return
    0x000e: 0x240e,  # SO/shift out
    0x000f: 0x240f,  # SI/shift in
    0x0010: 0x2410,  # DLE/data link escape
    0x0011: 0x2411,  # DC1/device control 1
    0x0012: 0x2412,  # DC2/device control 2
    0x0013: 0x2413,  # DC3/device control 3
    0x0014: 0x2414,  # DC4/device control 4
    0x0015: 0x2415,  # NAK/negative acknowledge
    0x0016: 0x2416,  # SYN/synchronous idle
    0x0017: 0x2417,  # ETB/end of transmission block
    0x0018: 0x2418,  # CAN/cancel
    0x0019: 0x2419,  # EM/end of medium
    0x001a: 0x241a,  # SUB/substitute
    0x001b: 0x241b,  # ESC/escape
    0x001c: 0x241c,  # FS/file separator
    0x001d: 0x241d,  # GS/group separator
    0x001e: 0x241e,  # RS/record separator
    0x001f: 0x241f,  # US/unit separator
    0x0020: 0x2420,  # SP/space
    0x007f: 0x2421,  # DEL/delete
}

REPLACEMENT_CHARACTER = chr(0xfffd)  # ?/replacement character


def render(bytez, encoding):
    # try:
    decoded = bytez.decode(encoding, 'replace')
    # except UnicodeDecodeError:
    #     decoded = ''

    decoded = ''.join(chr(CONTROLS.get(ord(c), ord(c))) for c in decoded)
    decoded = decoded.replace(REPLACEMENT_CHARACTER, ANSI_RED + REPLACEMENT_CHARACTER + ANSI_NORMAL)

    return decoded


def int2bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big') or b'\x00'


def bytes2int(bytez):
    return int.from_bytes(bytez, 'big')


def render_bytes_to_decimal(bytez, width):
    dec_bytez = ['___'] * width
    for i in range(len(bytez)):
        byte = bytez[-1 - i]
        dec_bytez[-1 - i] = "{:>03}".format(int(byte))
    return ' '.join(dec_bytez)


def render_bytes_to_hex(bytez, width):
    hex_bytes = ['__'] * width
    for i in range(len(bytez)):
        byte = bytez[-1 - i]
        hex_bytes[-1 - i] = "{:>02}".format(hex(byte)[2:].upper())
    return '  '.join(hex_bytes)


def render_row(bytez, width):
    int_padding = len(str(2**(8 * width)))
    sep = "\t"

    dec = render_bytes_to_decimal(bytez, width)
    hex_ = render_bytes_to_hex(bytez, width)

    rows = [str(len(bytez)), dec, hex_]
    rows += [render(bytez, enc) for enc in ENCODINGS]
    return sep.join(rows)


def render_bytes(bytez, width=None):
    return render_row(bytez, width=width or len(bytez))


def render_int(i, width=None):
    return render_row(int2bytes(i), width=width)


def analyze(bytez, from_encoding):
    print(f"Analyzing: {repr(bytez)}")
    print(f"Length in bytes: {len(bytez):,}")
    # print(f"({len(text)}-long, printing as {sys.getdefaultencoding()})\n")

    # try:
    #     text = bytez.decode(from_encoding)
    #     print(f"({len(text)}-long, decoding from '{from_encoding}')\n")
    # except UnicodeDecodeError:
    #     print(f"(Failed to decode as '{from_encoding}'!)\n")

    true_text = bytez.decode("utf-8")  # (we assert the input file is utf-8 encoded)
    print(f"As Unicode, from UTF-8: {repr(true_text)}")
    print(f"Unicode length, from UTF-8: {len(true_text):,}")
    print()

    try:
        new_bytez = true_text.encode(from_encoding)
    except UnicodeEncodeError:
        print(f"[!] Error:  The provided encoding ({from_encoding}) can't represent that Unicode, so this test makes no sense.")
        exit(1)

    return render_bytes(new_bytez)


def parse_args():
    parser = argparse.ArgumentParser(description="Analyze the relationship between text encodings")
    parser.add_argument("-f", "--file", help="File to analyze in all encodings")
    parser.add_argument("-e", "--encoding", help="The encoding to interpret the given text")
    return parser.parse_args()


def main():
    # print("\t".join([
    #     "Bytes",
    #     "Hex",
    #     "Decimal",
    #     "ASCII",
    #     "cp-1252 (Windows 8-bit)",
    #     "koi8_r (Russian 8-bit)",
    #     "UTF-8 (variable-width)",
    # ]))

    # for i in range(2**8):
    #     print(render_int(i, width=1))

    # for i in range(2**32):
    #     print(render_int(i, width=4))

    args = parse_args()

    'Ã“lafur'

    # print(repr(args.analyze))
    if not args.file or not args.encoding:
        exit("For now, requires --analyze and --encoding flags!")

    bytez = open(args.file, "rb").read()

    result = analyze(bytez, args.encoding)

    headers = [
        "Bytes",
        "Decimal",
        "Hex",
        "ASCII",
        "cp1252 (Windows 8-bit)",
        "latin1 (Western 8-bit)",
        "koi8_r (Russian 8-bit)",
        "utf-8 (variable-width)",
        "utf-16 (16-bit)",
        "utf-32 (32-bit)",
    ]

    for (h, r) in zip(headers, result.split('\t')):
        s = ANSI_BOLD if h.startswith(args.encoding) else ''
        e = ANSI_NORMAL if h.startswith(args.encoding) else ''
        print("{}{:>24}\t{}{}".format(s, h, r, e))


if __name__ == '__main__':
    main()
