/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 2
 * Author       : Tiago M. Dias (tiago.dias@isel.pt)
 * File         : enclave.h
 * Created      : 2026-11-09
 * Last modified: 2026-11-09
 * Description  : Declarations of utility functions available inside the enclave.
 */

#ifndef ENCLAVE_H
#define ENCLAVE_H

/*
 * printf-like helper for use inside an enclave.
 * The formatted text is sent to an untrusted output service via an OCALL.
 * Returns the number of characters written, or -1 on error/truncation.
 */
int enclave_printf( const char *format, ... );

#endif /* ENCLAVE_H */
