/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 2
 * Author       : Tiago M. Dias (tiago.dias@isel.pt)
 * File         : app.c
 * Created      : 2026-11-09
 * Last modified: 2026-11-09
 * Description  : Command-line application for generating passwords.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sgx_urts.h>
#include "sgx_utils.h"
#include "enclave_u.h"


#include "app.h"


/* Internal function declarations. */
static void show_help( const char *program_name );
static int parse_password_length( const char *text, long *length );

/*
 * Function   : main
 * Description: Process the command line and generate a password.
 * Inputs     : argc - number of command-line arguments.
 *              argv - array containing the arguments.
 * Outputs    : Returns EXIT_SUCCESS or EXIT_FAILURE.
 */
int main( int argc, char *argv[] )
{
    char password[PASSWORD_MAX_LENGTH + 1];
    long password_length = PASSWORD_DEFAULT_LENGTH;
    int option;
    int generate_requested = 0;

    sgx_enclave_id_t enclave_id = 0;
    sgx_status_t sgx_status;
    int ecall_return = EXIT_FAILURE;
    int exit_status = EXIT_FAILURE;


    /* Read the command-line options. */
    opterr = 0;
    while ( (option = getopt( argc, argv, ":ghl:" )) != -1 ) {
        switch ( option ) {
            case 'g':
                generate_requested = 1;
                break;
            case 'h':
                show_help( argv[0] );
                return EXIT_SUCCESS;
            case 'l':
                if ( parse_password_length( optarg, &password_length ) != 0 ) {
                    fprintf( stderr, "Invalid password length.\n" );
                    return EXIT_FAILURE;
                }
                break;
            case ':':
                fprintf( stderr, "Option -%c requires an argument.\n", optopt );
                return EXIT_FAILURE;
            default:
                fprintf( stderr, "Unknown option. Use -h for help.\n" );
                return EXIT_FAILURE;
        }
    }

    if ( !generate_requested || optind != argc ) {
        show_help( argv[0] );
        return EXIT_FAILURE;
    }

    /* Validate the password length before using it in the application. */
    if ( password_length < PASSWORD_MIN_LENGTH ||
         password_length > PASSWORD_MAX_LENGTH ) {
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

    /* Release enclave resources even when the ECALL failed. */
    sgx_status = sgx_destroy_enclave( enclave_id );
    if ( sgx_status != SGX_SUCCESS ) {
        fprintf( stderr, "Enclave destruction failed.\n" );
        print_sgx_error( sgx_status );
        exit_status = EXIT_FAILURE;
    }

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
    printf( "Usage: %s -g [-l length]\n", program_name );
    printf( "       %s -h\n\n", program_name );
    printf( "  -g          Generate a password\n" );
    printf( "  -l length   Password length (%d to %d, default %d)\n",
            PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_DEFAULT_LENGTH );
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

