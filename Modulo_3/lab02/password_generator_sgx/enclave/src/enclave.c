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


/* Characters that may appear in a generated password. */
static const char password_characters[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(){}[]:<>?,./";

/* Public ECALL declared in enclave.edl and called by the untrusted app. */
int ecall_generate_password(size_t len, char * buff, size_t buff_size)
{
    /* Validate the password length before using it in the application. */
    if ( len < PASSWORD_MIN_LENGTH ||
         len > PASSWORD_MAX_LENGTH ) {
        return EXIT_FAILURE;
    }

    /* Validate the buffer and its size. */
    if ( buff == NULL || buff_size < len + 1 ) {
        return EXIT_FAILURE;
    }

    /* Generate the password. */
    generate_password(buff, len);
    return EXIT_SUCCESS;
}

/*
 * Function   : generate_password
 * Description: Build a password by selecting characters at random.
 * Inputs     : password_length - requested number of characters.
 * Outputs    : password - NUL-terminated string in the caller's buffer.
 *              The caller must provide password_length + 1 bytes.
 */
void generate_password( char *password, size_t password_length )
{
    size_t index;
    const size_t character_count = strlen( password_characters );

    for ( index = 0; index < password_length; ++index ) {
        password[index] = password_characters[(size_t)rand() % character_count];
    }

    password[password_length] = '\0';
}
