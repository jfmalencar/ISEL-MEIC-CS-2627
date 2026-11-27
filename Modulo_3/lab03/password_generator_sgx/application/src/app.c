/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 3
 * Authors      : Jessé Ferreira de Moura Alencar (A51745)
 *                Rodrigo Dos Ramos Pais Henriques Vitorino (A49448)
 * File         : app.c
 * Created      : 2026-11-09
 * Last modified: 2026-11-27
 * Description  : Untrusted application: arguments, enclave lifecycle, sealed
 *                file storage and output.
 */

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_urts.h>
#include "sgx_utils.h"
#include "enclave_u.h"

#include "app.h"
#include "file_io.h"


/* Internal function declarations. */
static void show_help( const char *program_name );
static int parse_password_length( const char *text, long *length );
static int generate_and_show( sgx_enclave_id_t enclave_id, uint32_t password_length );
static int generate_and_save( sgx_enclave_id_t enclave_id, uint32_t password_length,
                              const char *output_file );
static int load_and_unseal( sgx_enclave_id_t enclave_id, const char *input_file );

/*
 * Function   : main
 * Description: Process the command line, create the enclave and generate,
 *              seal or unseal a password.
 * Inputs     : argc - number of command-line arguments.
 *              argv - array containing the arguments.
 * Outputs    : Returns EXIT_SUCCESS or EXIT_FAILURE.
 */
int main( int argc, char *argv[] )
{
    long password_length = PASSWORD_DEFAULT_LENGTH;
    int option;
    int generate_requested = 0;
    int length_specified = 0;
    const char *output_file = NULL;
    const char *input_file = NULL;

    sgx_enclave_id_t enclave_id = 0;
    sgx_status_t sgx_status;
    int exit_status;

    /* Read the command-line options. */
    opterr = 0;
    while ( (option = getopt( argc, argv, ":ghl:o:i:" )) != -1 ) {
        switch ( option ) {
            case 'g':
                generate_requested = 1;
                break;
            case 'h':
                show_help( argv[0] );
                return EXIT_SUCCESS;
            case 'l':
                length_specified = 1;
                if ( parse_password_length( optarg, &password_length ) != 0 ) {
                    fprintf( stderr, "Invalid password length.\n" );
                    return EXIT_FAILURE;
                }
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'i':
                input_file = optarg;
                break;
            case ':':
                fprintf( stderr, "Option -%c requires an argument.\n", optopt );
                return EXIT_FAILURE;
            default:
                fprintf( stderr, "Unknown option. Use -h for help.\n" );
                return EXIT_FAILURE;
        }
    }

    /* Select one operation (-g or -i) and reject incompatible options. */
    if ( optind != argc || generate_requested == (input_file != NULL) ||
         (input_file != NULL && (output_file != NULL || length_specified)) ||
         (output_file != NULL && output_file[0] == '\0') ||
         (input_file != NULL && input_file[0] == '\0') ) {
        fprintf( stderr, "Invalid option combination. Use -h for help.\n" );
        return EXIT_FAILURE;
    }

    /* Validate the password length before creating the enclave. */
    if ( generate_requested &&
         (password_length < PASSWORD_MIN_LENGTH ||
          password_length > PASSWORD_MAX_LENGTH) ) {
        fprintf( stderr, "Invalid password length (use %d to %d).\n",
                 PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH );
        return EXIT_FAILURE;
    }

    sgx_status = sgx_create_enclave( ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL );
    if ( sgx_status != SGX_SUCCESS ) {
        fprintf( stderr, "Enclave creation failed.\n" );
        print_sgx_error( sgx_status );
        return EXIT_FAILURE;
    }

    if ( input_file != NULL ) {
        exit_status = load_and_unseal( enclave_id, input_file );
    } else if ( output_file != NULL ) {
        exit_status = generate_and_save( enclave_id, (uint32_t)password_length, output_file );
    } else {
        exit_status = generate_and_show( enclave_id, (uint32_t)password_length );
    }

    /* Release enclave resources even when an operation failed. */
    sgx_status = sgx_destroy_enclave( enclave_id );
    if ( sgx_status != SGX_SUCCESS ) {
        fprintf( stderr, "Enclave destruction failed.\n" );
        print_sgx_error( sgx_status );
        exit_status = EXIT_FAILURE;
    }

    return exit_status;
}

/*
 * Function   : generate_and_show
 * Description: Generate a password inside the enclave and display it
 *              (original Lab 2 behaviour, used when -o is not given).
 * Inputs     : enclave_id - identifier of the loaded enclave.
 *              password_length - requested number of characters.
 * Outputs    : Returns EXIT_SUCCESS or EXIT_FAILURE.
 */
static int generate_and_show( sgx_enclave_id_t enclave_id, uint32_t password_length )
{
    char password[PASSWORD_MAX_LENGTH + 1];
    sgx_status_t sgx_status;
    int ecall_return = EXIT_FAILURE;
    int exit_status = EXIT_FAILURE;

    /*
     * ECALL results are separate:
     *   sgx_status   - whether the SDK could invoke the enclave function;
     *   ecall_return - the int returned by the function inside the enclave.
     */
    sgx_status = ecall_generate_password( enclave_id, &ecall_return,
                                          (size_t)password_length,
                                          password, sizeof(password) );
    if ( sgx_status != SGX_SUCCESS ) {
        fprintf( stderr, "Enclave call failed.\n" );
        print_sgx_error( sgx_status );
    } else if ( ecall_return != EXIT_SUCCESS ) {
        fprintf( stderr, "The enclave could not generate the password.\n" );
    } else {
        printf( "Generated password: %s\n", password );
        exit_status = EXIT_SUCCESS;
    }

    /* Remove the password from untrusted memory once it is no longer needed. */
    explicit_bzero( password, sizeof(password) );
    return exit_status;
}

/*
 * Function   : generate_and_save
 * Description: Ask the enclave for a sealed password and write the sealed
 *              blob to a binary file. The plaintext never reaches the
 *              application.
 * Inputs     : enclave_id - identifier of the loaded enclave.
 *              password_length - requested number of characters.
 *              output_file - path of the file to create or overwrite.
 * Outputs    : Returns EXIT_SUCCESS or EXIT_FAILURE.
 */
static int generate_and_save( sgx_enclave_id_t enclave_id, uint32_t password_length,
                              const char *output_file )
{
    uint8_t *sealed_data = NULL;
    uint32_t sealed_size = UINT32_MAX;
    sgx_status_t sgx_status;
    int ecall_return = EXIT_FAILURE;
    int exit_status = EXIT_FAILURE;

    /* 1. Ask the enclave how many bytes the sealed password needs. */
    sgx_status = ecall_get_sealed_size( enclave_id, &sealed_size, password_length );
    if ( sgx_status != SGX_SUCCESS ) {
        fprintf( stderr, "Enclave call failed.\n" );
        print_sgx_error( sgx_status );
        return EXIT_FAILURE;
    }
    if ( sealed_size == UINT32_MAX ) {
        fprintf( stderr, "The enclave could not calculate the sealed data size.\n" );
        return EXIT_FAILURE;
    }

    /* 2. Allocate the buffer that will receive the sealed blob. */
    sealed_data = malloc( sealed_size );
    if ( sealed_data == NULL ) {
        fprintf( stderr, "Could not allocate memory for the sealed data.\n" );
        return EXIT_FAILURE;
    }

    /* 3. Generate and seal the password inside the enclave. */
    sgx_status = ecall_generate_and_seal( enclave_id, &ecall_return, password_length,
                                          sealed_data, sealed_size );
    if ( sgx_status != SGX_SUCCESS ) {
        fprintf( stderr, "Enclave call failed.\n" );
        print_sgx_error( sgx_status );
    } else if ( ecall_return != EXIT_SUCCESS ) {
        fprintf( stderr, "The enclave could not generate and seal the password.\n" );
    } else if ( write_binary_file( output_file, sealed_data, sealed_size ) != 0 ) {
        /* 4. Store the sealed bytes in the output file. */
        fprintf( stderr, "Could not write the password file: %s\n", output_file );
    } else {
        printf( "Sealed password saved to %s (%u bytes).\n",
                output_file, (unsigned int)sealed_size );
        exit_status = EXIT_SUCCESS;
    }

    free( sealed_data );
    return exit_status;
}

/*
 * Function   : load_and_unseal
 * Description: Read a sealed blob from a binary file, ask the enclave to
 *              unseal it and display the recovered password.
 * Inputs     : enclave_id - identifier of the loaded enclave.
 *              input_file - path of the sealed file.
 * Outputs    : Returns EXIT_SUCCESS or EXIT_FAILURE.
 */
static int load_and_unseal( sgx_enclave_id_t enclave_id, const char *input_file )
{
    char password[PASSWORD_MAX_LENGTH + 1];
    unsigned char *file_data = NULL;
    size_t file_length = 0;
    sgx_status_t sgx_status;
    int ecall_return = EXIT_FAILURE;
    int exit_status = EXIT_FAILURE;

    /* 1. Read the sealed blob from the file. */
    if ( read_binary_file( input_file, &file_data, &file_length ) != 0 ) {
        fprintf( stderr, "Could not read the password file: %s\n", input_file );
        return EXIT_FAILURE;
    }

    /* The ECALL interface uses 32-bit sizes. */
    if ( file_length > UINT32_MAX ) {
        fprintf( stderr, "Invalid password file format.\n" );
        free( file_data );
        return EXIT_FAILURE;
    }

    /* 2. Unseal the password inside the enclave. */
    sgx_status = ecall_unseal_password( enclave_id, &ecall_return,
                                        file_data, (uint32_t)file_length,
                                        password, (uint32_t)sizeof(password) );
    if ( sgx_status != SGX_SUCCESS ) {
        fprintf( stderr, "Enclave call failed.\n" );
        print_sgx_error( sgx_status );
    } else if ( ecall_return != EXIT_SUCCESS ) {
        fprintf( stderr, "The enclave could not unseal the password.\n" );
        /* Values other than EXIT_FAILURE are the sgx_unseal_data() status. */
        if ( ecall_return != EXIT_FAILURE ) {
            print_sgx_error( (sgx_status_t)ecall_return );
        }
    } else {
        /* 3. Display the recovered password. */
        printf( "Recovered password: %s\n", password );
        exit_status = EXIT_SUCCESS;
    }

    /* Remove the password from untrusted memory once it is no longer needed. */
    explicit_bzero( password, sizeof(password) );
    free( file_data );
    return exit_status;
}

/*
 * Function   : show_help
 * Description: Display the available command-line options.
 * Inputs     : program_name - name used to invoke the application.
 * Outputs    : None.
 */
static void show_help( const char *program_name )
{
    printf( "Usage: %s -g [-l length] [-o filename]\n", program_name );
    printf( "       %s -i filename\n", program_name );
    printf( "       %s -h\n\n", program_name );
    printf( "  -g          Generate a password\n" );
    printf( "  -l length   Password length (%d to %d, default %d)\n",
            PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_DEFAULT_LENGTH );
    printf( "  -o filename Seal the generated password and save it in a binary file\n" );
    printf( "  -i filename Unseal and display a password stored in a binary file\n" );
    printf( "  -h          Display this help\n" );
}

/*
 * Function   : parse_password_length
 * Description: Convert a decimal argument into an integer value.
 * Inputs     : text - command-line argument to convert.
 * Outputs    : length - converted value when the argument is numeric.
 *              Returns 0 on success or -1 for an invalid number.
 */
static int parse_password_length( const char *text, long *length )
{
    char *end;

    *length = strtol( text, &end, 10 );
    if ( end == text || *end != '\0' ) {
        return -1;
    }

    return 0;
}
