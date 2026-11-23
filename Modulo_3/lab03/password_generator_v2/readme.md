# Password Generator v2

**Cybersecurity (Module 3 - Hardware Security) | Laboratory Activity #3**  
**Author:** Tiago M. Dias (tiago.dias@isel.pt)  
**Date:** 2026-11-16

## Purpose

This project extends the conventional password generator from Laboratory Activity #2. It adds command-line options and functions for reading and writing binary files. The application does not use the Intel SGX SDK.

## Project structure

```text
.
├── readme.md
├── Makefile
└── application/
    ├── src/
    │   ├── app.c
    │   └── file_io.c
    ├── inc/
    │   ├── app.h
    │   └── file_io.h
    ├── obj/
    └── bin/
```

The `src/` and `inc/` directories contain the source and header files. The `obj/` and `bin/` directories are used for generated build files.

## Compile

From the project root:

```bash
make
```

## Run

Run the executable from `application/bin/`:

```bash
cd application/bin
./password_generator -h
./password_generator -g -l 16
./password_generator -g -l 16 -o wallet.dat
./password_generator -i wallet.dat
cd ../..
```

Alternatively, execute `make run` from the project root.

## Clean

```bash
make clean
```
