/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 3
 * Author       : Tiago M. Dias (tiago.dias@isel.pt)
 * File         : app.c
 * Created      : 2026-11-09
 * Last modified: 2026-11-16
 * Description  : Password generator with command-line and binary file support.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"
#include "file_io.h"

/* Characters that may appear in a generated password. */
static const char password_characters[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(){}[]:<>?,./";

/* Internal function declarations. */
static void show_help( const char *program_name );
static int parse_password_length( const char *text, long *length );

/*
 * Function   : main
 * Description: Process the command line and generate or recover a password.
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
    unsigned char *file_data = NULL;
    size_t file_length = 0;
    const char *output_file = NULL;
    const char *input_file = NULL;
    int length_specified = 0;

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

    /* Select one operation and reject incompatible options. */
    if ( optind != argc || generate_requested == (input_file != NULL) ||
         (input_file != NULL && (output_file != NULL || length_specified)) ||
         (output_file != NULL && output_file[0] == '\0') ||
         (input_file != NULL && input_file[0] == '\0') ) {
        fprintf( stderr, "Invalid option combination. Use -h for help.\n" );
        return EXIT_FAILURE;
    }

    if ( generate_requested ) {
        /* Validate the password length before using it in the application. */
        if ( password_length < PASSWORD_MIN_LENGTH ||
             password_length > PASSWORD_MAX_LENGTH ) {
            fprintf( stderr, "Invalid password length (use %d to %d).\n",
                     PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH );
            return EXIT_FAILURE;
        }

        /* Initialize the pseudorandom generator using the current time. */
        srand( (unsigned int)time( NULL ) );
        generate_password( password, (size_t)password_length );

        if ( output_file != NULL ) {
            /* The binary file also includes the string's terminating byte. */
            if ( write_binary_file( output_file, (const unsigned char *)password,
                                    (size_t)password_length + 1 ) != 0 ) {
                fprintf( stderr, "Could not write the password file: %s\n", output_file );
                return EXIT_FAILURE;
            }
        }

        printf( "Generated password: %s\n", password );
        return EXIT_SUCCESS;
    }

    /* Read and validate the password stored in the binary file. */
    if ( read_binary_file( input_file, &file_data, &file_length ) != 0 ) {
        fprintf( stderr, "Could not read the password file: %s\n", input_file );
        return EXIT_FAILURE;
    }

    if ( file_length < PASSWORD_MIN_LENGTH + 1 ||
         file_length > PASSWORD_MAX_LENGTH + 1 ||
         file_data[file_length - 1] != '\0' ||
         strlen( (const char *)file_data ) != file_length - 1 ) {
        fprintf( stderr, "Invalid password file format.\n" );
        free( file_data );
        return EXIT_FAILURE;
    }

    printf( "Recovered password: %s\n", (const char *)file_data );
    free( file_data );
    return EXIT_SUCCESS;
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
    printf( "  -o filename Save the generated password in a binary file\n" );
    printf( "  -i filename Read a password from a binary file\n" );
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
