# IRSCANNER

IRSCANNER is a small incident-response binary triage utility written in strict ANSI Fortran 77.

It is intended for first-pass examination of suspicious or unknown files. It does not replace a full forensic workflow, but it can quickly highlight properties that are often useful during incident response, malware triage, and basic binary inspection. As it is coded in F77, it can compile on older legacy systems and IoT easily, and has no dependencies. 

## What it is for

IRSCANNER reads a target file as raw bytes and produces a human-readable report covering:

- file size and read mode
- recognised file signatures for some common formats
- global Shannon entropy
- sliding-window entropy
- dominant byte and null-byte percentage
- single-byte XOR detection and likely key recovery
- repeating-key XOR detection and likely key recovery for short keys
- byte diversity
- long runs of repeated bytes
- top byte frequencies
- short decoded previews when XOR recovery is strong enough

This makes it useful for spotting things such as:

- compressed or packed content
- encrypted-looking blobs
- all-zero files
- sparse or null-heavy files
- possible XOR-obfuscated payloads
- unusually repetitive regions
- obvious file headers such as ELF, ZIP, PDF, PNG, JPEG, and similar formats

IRSCANNER is a triage tool. Its output is heuristic and should be treated as analyst guidance, not formal proof.

## Operating systems

The source is written in strict ANSI Fortran 77 and is intended to be portable across systems that have a suitable Fortran compiler and support direct-access unformatted file I/O in the usual way.

It is intended to run on:

- Linux
- other Unix-like systems
- RISC OS systems with an appropriate Fortran 77 compiler
- Windows, if compiled with a suitable Fortran compiler

In practice, the most straightforward targets are:

- Linux with `gfortran`
- Unix-like systems with `gfortran` or another compatible Fortran compiler
- RISC OS with an Acorn/Norcroft-compatible Fortran environment

This README focuses on Linux and Unix usage.

## Supported runtime behaviour

On standard byte-addressed runtimes such as `gfortran` on Linux, IRSCANNER performs byte-accurate reads.

The source also contains logic for runtimes that use word-based direct-access record units. On such systems, behaviour is designed to remain usable for triage, but platform-specific compiler and runtime details may still matter.

## Building on Linux / Unix

### Using gfortran

```sh
 gfortran -std=legacy -O2 -o irscanner irscanner.f
```

If you want a more self-contained Linux binary, you can also try:

```sh
 gfortran -std=legacy -O2 -static-libgfortran -static-libgcc \
   -o irscanner irscanner.f
```

Static linking may not always be available on every system.

### Compiler notes

The source is written in fixed-form Fortran 77 style. Use a compiler mode that accepts legacy fixed-form source if required.

## Using IRSCANNER on Linux / Unix

IRSCANNER reads the target filename from standard input.

Run it like this:

```sh
 ./irscanner
```

It will prompt:

```text
 Enter target filename:
```

Type the path to the file and press Enter.

### Non-interactive use

You can also pass the filename through standard input:

```sh
 printf 'sample.bin\n' | ./irscanner
```

### Saving a report

```sh
 printf 'sample.bin\n' | ./irscanner > sample_report.txt
```

### Testing several files

```sh
 for f in plain.txt zeros.bin random.bin xor_text.bin elf_sample.bin xor_rep.bin
 do
   echo "===== $f ====="
   printf '%s\n' "$f" | ./irscanner
   echo
 done
```

## Interpreting the report

### File summary

Shows the byte count, read path, and any recognised file format signature.

### Entropy analysis

Higher entropy may indicate encrypted, compressed, or packed data. Lower entropy usually suggests plaintext, structured data, or repetitive content.

### XOR sections

IRSCANNER can try to identify:

- single-byte XOR
- short repeating-key XOR, currently limited to short keys

When the evidence is strong enough, it reports a likely key and a short decoded preview.

These findings are still heuristic. A likely key recovery is a strong lead, not an automatic guarantee.

### Byte diversity

Shows how many distinct byte values appear in the file. Extremely low diversity may indicate a very restricted encoding, padding, a test file, or an all-zero file.

### Repeated-byte runs

Flags long runs of the same byte. In some cases this may indicate padding, alignment, fill patterns, or staging regions.

### Top byte frequencies

Shows the most common byte values and their approximate percentages.

## Example test files

The following harmless files are useful for testing:

- a small text file
- an all-zero file
- a random file from `/dev/urandom`
- a normal executable such as `/bin/ls`
- a file encoded with single-byte XOR
- a file encoded with short repeating-key XOR

Example commands:

```sh
 printf 'This is a plain text test file.\n' > plain.txt
 dd if=/dev/zero of=zeros.bin bs=1 count=4096
 dd if=/dev/urandom of=random.bin bs=1 count=4096
 cp /bin/ls elf_sample.bin
 python3 - <<'PY'
 data = b'This is a test of single-byte XOR recovery.\n' * 20
 key = 0x5A
 open('xor_text.bin', 'wb').write(bytes([b ^ key for b in data]))
 PY
 python3 - <<'PY'
 data = b'This is repeating-key XOR test data.\n' * 30
 key = b'ICE'
 out = bytearray()
 for i, b in enumerate(data):
     out.append(b ^ key[i % len(key)])
 open('xor_rep.bin', 'wb').write(out)
 PY
```

## Limitations

- IRSCANNER is a triage tool, not a full malware-analysis framework.
- Entropy and frequency-based findings are heuristic.
- XOR detection is limited to single-byte XOR and short repeating-key XOR.
- File signature recognition is based on a small set of common headers.
- A recognised signature or likely recovered key should still be validated with other tools.

## Typical workflow on Linux / Unix

A simple workflow is:

1. compile the tool
2. run it against the suspicious file
3. review entropy, XOR, format, and repeat-pattern sections
4. follow up with deeper tools if something looks unusual

For example:

```sh
 gfortran -std=legacy -O2 -o irscanner irscanner_v1_9_ansi_f77.f
 printf 'suspect.bin\n' | ./irscanner > suspect_report.txt
 less suspect_report.txt
```
