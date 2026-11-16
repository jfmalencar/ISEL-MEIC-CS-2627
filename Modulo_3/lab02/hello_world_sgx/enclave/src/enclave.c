/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 2
 * Author       : Tiago M. Dias (tiago.dias@isel.pt)
 * File         : enclave.c
 * Created      : 2026-11-09
 * Last modified: 2026-11-09
 * Description  : Trusted enclave code and reusable formatted output helper.
 */

#include <stdarg.h>
#include <stdio.h>  /* vsnprintf(), available in the trusted C library. */

#include "enclave.h"
#include "enclave_t.h"  /* Generated OCALL declaration from enclave.edl. */

#define ENCLAVE_PRINT_BUFFER_SIZE 256

/* This message is public information, not a secret. */
static const char hello_message[] = "Hello SGX World!";

/* Public ECALL declared in enclave.edl and called by the untrusted app. */
int ecall_hello_message( void )
{
    if ( enclave_printf( "%s\n", hello_message ) < 0 ) {
        return -1;
    }

    return 0;
}

int enclave_printf( const char *format, ... ) {

    char buffer[ENCLAVE_PRINT_BUFFER_SIZE];
    va_list args;
    int length;
    sgx_status_t sgx_status;

    /* Format the message in enclave memory before transferring it. */
    va_start( args, format );
    length = vsnprintf( buffer, sizeof(buffer), format, args );
    va_end(args);

    /* Reject formatting errors and messages larger than the local buffer. */
    if ( length < 0 || (size_t)length >= sizeof(buffer) ) {
        return -1;
    }

    /* Printing happens outside the enclave, through the OCALL. */
    sgx_status = ocall_print_string( buffer );
    if ( sgx_status != SGX_SUCCESS ) {
        return -1;
    }

    return length;  /* Like printf(), this excludes the terminating NUL. */
}

