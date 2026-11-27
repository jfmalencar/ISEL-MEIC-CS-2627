/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 3
 * Authors      : Jessé Ferreira de Moura Alencar (A51745)
 *                Rodrigo Dos Ramos Pais Henriques Vitorino (A49448)
 * File         : enclave.c
 * Created      : 2026-11-09
 * Last modified: 2026-11-27
 * Description  : Trusted enclave code: password generation with sgx_read_rand().
 */

#include <string.h>     /* strlen(), memset() */
#include "sgx_trts.h"   /* sgx_read_rand() */
#include "sgx_tseal.h"  /* funções de seal e unseal*/
#include <stdint.h>

#include "enclave.h"
#include "enclave_t.h"  /* Generated OCALL declaration from enclave.edl. */


/*
 * Attribute and MISCSELECT masks used by sgx_seal_data_ex(). The values are
 * the ones recommended in the Intel SGX Developer Reference (the same used
 * internally by sgx_seal_data()); defined here only if the SDK headers do not.
 */
#ifndef TSEAL_DEFAULT_FLAGSMASK
#define TSEAL_DEFAULT_FLAGSMASK 0xFF0000000000000BULL
#endif
#ifndef TSEAL_DEFAULT_MISCMASK
#define TSEAL_DEFAULT_MISCMASK  0xF0000000U
#endif

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
 * Function   : ecall_get_sealed_size
 * Description: Public ECALL that reports the number of bytes needed to store
 *              a sealed password of the requested length.
 * Inputs     : password_length - requested number of characters.
 * Outputs    : Returns the sealed data size, or UINT32_MAX if the length
 *              is invalid.
 */
uint32_t ecall_get_sealed_size( uint32_t password_length )
{
    /* Validate the password length before calculating the size. */
    if ( password_length < PASSWORD_MIN_LENGTH ||
         password_length > PASSWORD_MAX_LENGTH ) {
        return UINT32_MAX;
    }

    /* No additional authenticated data; encrypt the string and its '\0'.
     * sgx_calc_sealed_data_size() itself returns UINT32_MAX on error. */
    return sgx_calc_sealed_data_size( 0, password_length + 1 );
}

/*
 * Function   : ecall_generate_and_seal
 * Description: Public ECALL that generates a password and returns only its
 *              sealed representation. The plaintext never leaves the enclave.
 * Inputs     : password_length - requested number of characters.
 *              sealed_capacity - size of the sealed_data buffer.
 * Outputs    : sealed_data - buffer that receives the sealed blob.
 *              Returns EXIT_SUCCESS or EXIT_FAILURE.
 */
int ecall_generate_and_seal( uint32_t password_length, uint8_t *sealed_data,
                             uint32_t sealed_capacity )
{
    char password[PASSWORD_MAX_LENGTH + 1];
    uint32_t sealed_size;
    sgx_attributes_t attribute_mask;
    sgx_status_t status;

    /* Validate the password length and the output buffer. */
    if ( password_length < PASSWORD_MIN_LENGTH ||
         password_length > PASSWORD_MAX_LENGTH || sealed_data == NULL ) {
        return EXIT_FAILURE;
    }

    /* Check that the sealed blob fits in the buffer provided. */
    sealed_size = sgx_calc_sealed_data_size( 0, password_length + 1 );
    if ( sealed_size == UINT32_MAX || sealed_capacity < sealed_size ) {
        return EXIT_FAILURE;
    }

    /* Generate the password in enclave memory (same function as the
     * ecall_generate_password ECALL). */
    if ( generate_password( password, password_length ) != 0 ) {
        return EXIT_FAILURE;
    }

    /*
     * Seal to the current enclave (MRENCLAVE policy). sealed_data already
     * points to trusted memory: for an [out] parameter, the edge routine
     * allocates the buffer inside the enclave and copies it to the
     * application's buffer when the ECALL returns.
     */
    attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    attribute_mask.xfrm  = 0x0;
    status = sgx_seal_data_ex( SGX_KEYPOLICY_MRENCLAVE, attribute_mask,
                               TSEAL_DEFAULT_MISCMASK,
                               0, NULL,
                               password_length + 1, (const uint8_t *)password,
                               sealed_size, (sgx_sealed_data_t *)sealed_data );

    /* The plaintext password never leaves the enclave. */
    memset( password, 0, sizeof(password) );

    return ( status == SGX_SUCCESS ) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*
 * Function   : ecall_unseal_password
 * Description: Public ECALL that unseals a password stored in a sealed blob.
 * Inputs     : sealed_data - sealed blob read from the file.
 *              sealed_size - number of bytes in sealed_data.
 *              password_capacity - size of the password buffer.
 * Outputs    : password - NUL-terminated recovered password.
 *              Returns EXIT_SUCCESS, EXIT_FAILURE or an sgx_status_t value
 *              if sgx_unseal_data() fails.
 */
int ecall_unseal_password( const uint8_t *sealed_data, uint32_t sealed_size,
                           char *password, uint32_t password_capacity )
{
    const sgx_sealed_data_t *sealed_blob = (const sgx_sealed_data_t *)sealed_data;
    char plaintext[PASSWORD_MAX_LENGTH + 1];
    uint32_t text_length;
    uint32_t mac_text_length;
    uint32_t plaintext_length;
    sgx_status_t status;

    /* Validate the buffers and make sure the blob holds at least the header. */
    if ( sealed_data == NULL || password == NULL ||
         sealed_size < sizeof(sgx_sealed_data_t) ) {
        return EXIT_FAILURE;
    }

    /* Read the sizes recorded in the blob and check them against the
     * number of bytes actually received. */
    text_length     = sgx_get_encrypt_txt_len( sealed_blob );
    mac_text_length = sgx_get_add_mac_txt_len( sealed_blob );
    if ( text_length == UINT32_MAX || mac_text_length != 0 ||
         sgx_calc_sealed_data_size( 0, text_length ) != sealed_size ) {
        return EXIT_FAILURE;
    }

    /* The plaintext must be a valid password plus its '\0' and fit in the
     * local and output buffers. */
    if ( text_length < PASSWORD_MIN_LENGTH + 1 ||
         text_length > PASSWORD_MAX_LENGTH + 1 ||
         password_capacity < text_length ) {
        return EXIT_FAILURE;
    }

    /* Decrypt and verify the blob (fails if it was modified or was sealed
     * by a different enclave). */
    plaintext_length = text_length;
    status = sgx_unseal_data( sealed_blob, NULL, NULL,
                              (uint8_t *)plaintext, &plaintext_length );
    if ( status != SGX_SUCCESS ) {
        memset( plaintext, 0, sizeof(plaintext) );
        return (int)status;   /* e.g. SGX_ERROR_MAC_MISMATCH (0x3001) */
    }

    /* Check that the recovered data is a NUL-terminated string of the
     * expected length. */
    if ( plaintext_length != text_length ||
         plaintext[plaintext_length - 1] != '\0' ||
         strlen( plaintext ) != plaintext_length - 1 ) {
        memset( plaintext, 0, sizeof(plaintext) );
        return EXIT_FAILURE;
    }

    memcpy( password, plaintext, plaintext_length );
    memset( plaintext, 0, sizeof(plaintext) );
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


