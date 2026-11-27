/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 2
 * Authors      : Jessé Ferreira de Moura Alencar (A51745)
 *                Rodrigo Dos Ramos Pais Henriques Vitorino (A49448)
 * File         : enclave.c
 * Created      : 2026-11-09
 * Last modified: 2026-11-21
 * Description  : Trusted enclave code: password generation with sgx_read_rand().
 */

#include <string.h>     /* strlen(), memset() */
#include "sgx_trts.h"   /* sgx_read_rand() */


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
    if ( generate_password( buff, len ) != 0 ) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;

}

/*
 * Function   : generate_password
 * Description: Build a password by selecting characters at random,
 *              using the SGX trusted random number generator.
 * Inputs     : password_length - requested number of characters.
 * Outputs    : password - NUL-terminated string in the caller's buffer.
 *              The caller must provide password_length + 1 bytes.
 *              Returns 0 on success or -1 if random generation fails.
 */
int generate_password( char *password, size_t password_length )
{
    const size_t character_count = strlen( password_characters );
    /* Largest multiple of character_count that fits in a byte (0..255).
     * Bytes >= limit are rejected so every character is equally likely. */
    const unsigned int limit = 256u - (256u % (unsigned int)character_count);
    unsigned char random_byte;
    size_t index = 0;

    while ( index < password_length ) {
        if ( sgx_read_rand( &random_byte, sizeof(random_byte) ) != SGX_SUCCESS ) {
            memset( password, 0, password_length + 1 );  /* Leave no partial password. */
            return -1;
        }

        if ( random_byte >= limit ) {
            continue;  /* Discard to avoid modulo bias. */
        }

        password[index++] = password_characters[random_byte % character_count];
    }

    password[password_length] = '\0';
    return 0;
}