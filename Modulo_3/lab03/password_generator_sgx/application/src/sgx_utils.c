/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 2
 * Author       : Tiago M. Dias (tiago.dias@isel.pt)
 * File         : sgx_utils.c
 * Created      : 2026-11-09
 * Last modified: 2026-11-09
 * Description  : SGX runtime error descriptions and diagnostic output.
 * Attribution  : SGX error-table entries adapted from Intel SGX SDK examples.
 */

#include <stddef.h>
#include <stdio.h>

#include "sgx_utils.h"

typedef struct {
    sgx_status_t code;
    const char *message;
    const char *suggestion;
} sgx_error_entry_t;

/* Selected SDK errors useful when diagnosing enclave lifecycle problems. */
static const sgx_error_entry_t sgx_error_table[] = {
    { SGX_ERROR_UNEXPECTED,            "Unexpected SGX error.", NULL },
    { SGX_ERROR_INVALID_PARAMETER,     "Invalid parameter.", NULL },
    { SGX_ERROR_OUT_OF_MEMORY,         "Out of memory.", NULL },
    { SGX_ERROR_ENCLAVE_LOST,          "The enclave was lost.", NULL },
    { SGX_ERROR_INVALID_ENCLAVE,       "Invalid enclave image.", NULL },
    { SGX_ERROR_INVALID_ENCLAVE_ID,    "Invalid enclave identifier.", NULL },
    { SGX_ERROR_INVALID_SIGNATURE,     "Invalid enclave signature.", NULL },
    { SGX_ERROR_OUT_OF_EPC,            "Insufficient EPC memory.", NULL },
    { SGX_ERROR_NO_DEVICE,             "SGX runtime/device is unavailable.", "Check the selected execution mode and SDK runtime." },
    { SGX_ERROR_MEMORY_MAP_CONFLICT,   "Memory map conflict.", NULL },
    { SGX_ERROR_INVALID_METADATA,      "Invalid enclave metadata.", NULL },
    { SGX_ERROR_DEVICE_BUSY,           "SGX device is busy.", NULL },
    { SGX_ERROR_INVALID_VERSION,       "Invalid enclave version.", NULL },
    { SGX_ERROR_INVALID_ATTRIBUTE,     "Enclave attributes are not permitted.", NULL },
    { SGX_ERROR_ENCLAVE_FILE_ACCESS,   "Cannot access the enclave image.",
                                      "Check the signed enclave filename and location." }
};

void print_sgx_error(sgx_status_t status)
{
    size_t index;
    size_t count = sizeof( sgx_error_table ) / sizeof( sgx_error_table[0] );

    for ( index = 0; index < count; ++index ) {
        if ( sgx_error_table[index].code == status ) {
            fprintf( stderr, "SGX error 0x%04X: %s\n", (unsigned int)status, sgx_error_table[index].message );
            if ( sgx_error_table[index].suggestion != NULL ) {
                fprintf( stderr, "Hint: %s\n", sgx_error_table[index].suggestion );
            }
            return;
        }
    }

    /* Keep the numeric code visible when an SDK version adds a new error. */
    fprintf( stderr, "SGX error 0x%04X: consult the SGX SDK Developer Reference.\n", (unsigned int)status );
}
