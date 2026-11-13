# CTF quick cheatsheet (seed — extend with your own notes)

A small starter so `knowledge` returns something out of the box. Replace/augment
with your `ctf-notes`.

## Triage (any file)
- `file`, `strings -n 6`, `xxd | head`, `binwalk`, `exiftool`. Archives: `7z l`,
  `unzip -l`. Entropy high + no type → encrypted/compressed/packed (`upx -d`).
- Encodings to try: base64, base32, hex, URL, ROT13/47, gzip/zlib, uuencode.

## Reverse engineering
- Decompile key function with Ghidra headless; cross-check in radare2 (`aaa; pdf`).
- Dynamic: gdb+pwndbg batch, `ltrace`/`strace`. Foreign arch → `qemu-*-static` +
  `gdb-multiarch`. Constraint/keygen checks → `angr` or `z3`. Emulate opaque byte
  streams → `unicorn`. `.pyc` → `uncompyle6`/`decompyle3`.

## Pwn (binary exploitation)
- `checksec` first. Classic ladder: leak → libc base → ROP/one_gadget → shell.
- libc challenges: identify libc, `pwninit`/`patchelf`, gadgets via
  `ROPgadget`/`ropper`/`one_gadget`, filters via `seccomp-tools`.
- Heap: tcache poisoning, House of Force/Orange/Apple, FSOP, fastbin dup.
- Write the exploit as pwntools; verify each primitive locally, then go remote.

## Crypto
- RSA: small e (cube root), Wiener (small d), common modulus, Hastad broadcast,
  Franklin-Reiter, partial-key Coppersmith (Sage). Factor locally with `yafu`
  (no internet for factordb). Classical: `xortool`, frequency analysis.
- ECC / lattice / discrete log → **SageMath** (discrete_log, LLL via fpylll).
- Padding oracle → scripted bit-flipping. Hash length-extension → `hashpump`.

## Web
- Map first (whatweb, ffuf/feroxbuster + SecLists). Then the implied bug: SQLi
  (sqlmap), command injection (commix), SSRF/LFI/traversal, auth/JWT (jwt_tool),
  Flask session forge (flask-unsign), SSTI, deserialization.

## Forensics / stego
- Memory → Volatility 3 (pslist, cmdline, filescan/dumpfiles, netscan).
- Disk → sleuthkit (fls/icat). PCAP → tshark (follow/ export objects).
- Images: zsteg (PNG/BMP LSB), steghide/stegseek (JPEG, crack w/ rockyou),
  outguess, zsteg; QR → zbarimg; audio → sox spectrogram, multimon-ng. Text in an
  image → `tesseract` OCR (preprocess with imagemagick).

## Blockchain (EVM)
- `slither` for vulns; `cast storage`/`code`/`call` to read state. Bugs:
  reentrancy, access control, delegatecall/tx.origin, uninitialized storage,
  unchecked return, overflow (<0.8). Drive `isSolved()` with `cast send`/web3.

## Pyjail
- Pin the filter + Python version + audit hooks. Escapes:
  `().__class__.__base__.__subclasses__()`, `__import__`, `__builtins__`,
  `getattr` chains, `breakpoint()`, `__reduce__`, bytecode. Goal: read the flag
  file or spawn a shell.
