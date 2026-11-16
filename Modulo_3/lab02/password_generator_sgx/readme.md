# Intel SGX Project Skeleton

**Cybersecurity – Module 3: Hardware Security**  
**Instituto Superior de Engenharia de Lisboa (ISEL)**

## Purpose

This project provides the **basic directory structure** for developing Intel SGX applications in the Cybersecurity course at ISEL. It includes a `Makefile` and the essential enclave configuration files so that students can develop their applications without having to set up the project from scratch.

The skeleton does **not** include the application or enclave C source code. Students must add the source files required by their projects.

## Project structure

```text
.
├── readme.md
├── Makefile
├── application/
│   ├── src/        # Untrusted application source files (.c)
│   ├── inc/        # Untrusted application header files (.h)
│   ├── obj/        # Generated object files
│   └── bin/        # Application executable and signed enclave
└── enclave/
    ├── src/        # Trusted enclave source files (.c)
    ├── inc/        # Trusted enclave header files (.h)
    ├── conf/       # Enclave interface and configuration files
    ├── obj/        # Generated object files
    └── bin/        # Unsigned enclave library
```

The output filenames can be changed using the `APP_NAME`, `ENCLAVE_NAME` and `SIGNED_ENCLAVE_NAME` variables in the `Makefile`.

The following files are provided in `enclave/conf/`:

- `enclave.edl` — declares the enclave interface (ECALLs and OCALLs). The declarations must be completed for each application.
- `enclave.config.xml` — enclave configuration settings.
- `enclave.lds` — enclave linker script.
- `enclave_private_test.pem` — development signing key, **not intended for production use**.

The `obj/` and `bin/` directories are used for files produced during compilation and should not be edited manually.

## Laboratory environment

The project is intended to be built and run **from the Linux command line** on the Ubuntu laboratory VM. The Intel SGX SDK is installed at:

```text
/opt/intel/sgxsdk
```

The VM is already configured for SGX development. There is no need to run `source` or manually initialize the SDK environment.

The laboratory uses **SGX simulation mode** (`SGX_MODE=SIM`), with debugging enabled by default (`SGX_DEBUG=1`). Simulation mode supports the SGX programming interfaces but does not provide hardware-enforced enclave isolation.

## Building the application

After adding the required source code and enclave interface declarations, run the following command from the **project root directory** (the directory containing the `Makefile`):

```bash
make
```

The skeleton cannot produce a working application until the required source files have been added.

## Running the application

After a successful build, run the application from the project root:

```bash
make run
```

## Cleaning the project

To remove the generated build files, run:

```bash
make clean
```

You can then rebuild the project with `make`.
