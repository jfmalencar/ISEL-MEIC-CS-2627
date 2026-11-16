# Password Generator

**Cybersecurity (Module 3 - Hardware Security) | Laboratory Activity #2**  
**Author:** Tiago M. Dias (tiago.dias@isel.pt)  
**Date:** 2026-11-09

## Purpose

This project contains a small conventional C application used in Laboratory Activity #2. It provides the source code and a Makefile for building and running a password generator from the Linux command line. Students will examine and adapt the program during the laboratory exercises.

## Project structure

```text
.
├── readme.md
├── Makefile
└── application/
    ├── src/
    │   └── app.c
    ├── inc/
    │   └── app.h
    ├── obj/
    └── bin/
```

The `src/` and `inc/` directories contain source and header files. The `obj/` and `bin/` directories hold generated build files and should not be edited manually.

## Compile

From the project root, run:

```bash
make
```

## Run

Run the program with the default arguments:

```bash
make run
```

The executable also accepts command-line options:

```bash
./application/bin/password_generator -g -l 16
./application/bin/password_generator -h
```

The supported password lengths range from 8 to 100 characters. Alternatively, change the arguments used by `make run`:

```bash
make run RUN_ARGS="-g -l 24"
```

## Clean

Remove generated files with:

```bash
make clean
```

## Note

This conventional program is intended for laboratory analysis and adaptation. It is not a production password-management application.
