#!/usr/bin/env python3
"""Convert between WireGuard/AmneziaWG .conf files and AmneziaVPN text keys."""

import argparse
import base64
import json
import os
import re
import sys
import tempfile
import zlib
from pathlib import Path


PREFIX = "vpn://"
INTERFACE = re.compile(rb"^(?:\xef\xbb\xbf)?[ \t]*\[Interface\][ \t]*(?:[#;][^\r\n]*)?\r?$", re.M)


def encode(config):
    if not INTERFACE.search(config):
        raise ValueError("the input file needs an [Interface] section")
    # Qt's qCompress stores the uncompressed byte count before the zlib stream.
    packed = len(config).to_bytes(4, "big") + zlib.compress(config, 8)
    return PREFIX + base64.urlsafe_b64encode(packed).rstrip(b"=").decode("ascii")


def unpack(link):
    link = link.strip()
    if not link.startswith(PREFIX):
        raise ValueError("expected a link starting with vpn://")
    token = link[len(PREFIX):]
    try:
        packed = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
    except ValueError:
        raise ValueError("invalid Base64 in vpn:// link") from None

    size = int.from_bytes(packed[:4], "big")
    stream = zlib.decompressobj()
    try:
        payload = stream.decompress(packed[4:], size + 1)
    except zlib.error:
        # AmneziaVPN also accepts Base64 of uncompressed config text or JSON.
        if b"\0" not in packed and (INTERFACE.search(packed) or
                                    packed.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"{")):
            return packed
        raise ValueError("invalid compressed data in vpn:// link") from None
    if not stream.eof or stream.unused_data or len(payload) != size:
        raise ValueError("incomplete link or incorrect uncompressed length")
    return payload


def decode(link):
    payload = unpack(link)
    if INTERFACE.search(payload):
        return payload

    # Share exports store the native text in containers[].awg/wireguard.last_config.
    profile = json.loads(payload)
    containers = profile.get("containers") if isinstance(profile, dict) else None
    if not isinstance(containers, list):
        raise ValueError("this link has no embedded WireGuard or AmneziaWG .conf")
    matches = []
    for container in containers:
        if not isinstance(container, dict):
            continue
        protocol = container.get("awg") or container.get("wireguard")
        if not isinstance(protocol, dict):
            continue
        client = protocol.get("last_config")
        if isinstance(client, str) and client:
            client = json.loads(client)
        config = client.get("config") if isinstance(client, dict) else None
        if isinstance(config, str) and INTERFACE.search(config.encode("utf-8")):
            matches.append((container.get("container"), config))

    if not matches:
        raise ValueError("this link has no embedded WireGuard or AmneziaWG .conf")
    if len(matches) > 1:
        matches = [match for match in matches if match[0] == profile.get("defaultContainer")]
        if len(matches) != 1:
            raise ValueError("this link contains multiple configs without a unique default")
    config = matches[0][1]
    for placeholder, field in (("$PRIMARY_DNS", "dns1"), ("$SECONDARY_DNS", "dns2")):
        if placeholder in config:
            value = profile.get(field)
            if isinstance(value, str) and len(value.strip().splitlines()) == 1:
                config = config.replace(placeholder, value.strip())
            else:
                print(f"warning: set {placeholder} in the decoded config", file=sys.stderr)
    return config.encode("utf-8")


def save_config(path, config):
    # A same-directory temporary file gives private permissions and atomic replacement.
    temp = tempfile.NamedTemporaryFile(dir=path.parent, delete=False)
    try:
        with temp:
            temp.write(config)
        os.replace(temp.name, path)
    except BaseException:
        os.unlink(temp.name)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    encoder = commands.add_parser("encode", help="print a vpn:// link")
    encoder.add_argument("config", type=Path, metavar="config.conf")
    decoder = commands.add_parser("decode", help="extract a .conf from a vpn:// link")
    decoder.add_argument("link", metavar="vpn://...")
    decoder.add_argument("-o", dest="output", type=Path, metavar="config.conf",
                         help="write or replace this file (default: stdout)")
    args = parser.parse_args()

    try:
        if args.command == "encode":
            print(encode(args.config.read_bytes()))
        else:
            config = decode(args.link)
            if args.output is None:
                sys.stdout.buffer.write(config)
            else:
                save_config(args.output, config)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")


if __name__ == "__main__":
    main()
