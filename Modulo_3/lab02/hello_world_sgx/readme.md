# Intel SGX Hello World

**Cybersecurity (Module 3 – Hardware Security) | Laboratory Activity #2**  
**Author:** Tiago M. Dias (tiago.dias@isel.pt)  
**Date:** 2026-11-09

## Purpose

This project provides a small Intel SGX application for use in Laboratory Activity #2. It includes the source code, project configuration and build rules needed to compile and run the example in the laboratory environment. The program will be examined as part of the practical exercises.

## Laboratory environment

The project is designed to be compiled and run **from the Linux command line** on the Ubuntu laboratory VM. The Intel SGX SDK is installed at:

```text
/opt/intel/sgxsdk
```

The Makefile uses this path by default. The VM is already configured, so there is **no need to execute `source`** or initialize the SDK environment manually.

The default configuration uses **SGX simulation mode** (`SGX_MODE=SIM`) with debugging enabled (`SGX_DEBUG=1`). Simulation mode provides the software interfaces but does not enforce hardware-based enclave isolation.

## Project structure

```text
.
├── readme.md
├── Makefile
├── application/
│   ├── src/
│   │   ├── app.c
│   │   └── sgx_utils.c
│   ├── inc/
│   │   ├── app.h
│   │   └── sgx_utils.h
│   ├── obj/
│   └── bin/
└── enclave/
    ├── src/
    │   └── enclave.c
    ├── inc/
    │   └── enclave.h
    ├── conf/
    │   ├── enclave.edl
    │   ├── enclave.config.xml
    │   ├── enclave.lds
    │   └── enclave_private_test.pem
    ├── obj/
    └── bin/
```

The `src/` directories contain source files, `inc/` directories contain header files, and `conf/` holds project configuration. The `obj/` and `bin/` directories are used for generated build files and should not be edited manually.

## Compile

From the project root, where the `Makefile` is located, run:

```bash
make
```

A successful build produces the application executable and the enclave files in the corresponding `bin/` directories. The signing key provided in `enclave/conf/` is intended **only for laboratory development**, not for production use.

## Run

Execute the application from the project root:

```bash
make run
```

## Clean

To remove generated build files, run:

```bash
make clean
```

Compile the project again with `make` when needed.

## Troubleshooting

- **Application or enclave file not found:** run `make` from the project root and execute the program with `make run`.
- **Build errors after changing interface declarations:** run `make clean` followed by `make`. Do not edit generated build files manually.
- **SDK files not found:** verify that the installation exists at `/opt/intel/sgxsdk`.
- **SGX execution error:** record the reported status code and consult the Intel SGX SDK Developer Reference.
