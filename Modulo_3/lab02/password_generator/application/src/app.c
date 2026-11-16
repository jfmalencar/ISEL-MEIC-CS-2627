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

#include "app.h"

/* Characters that may appear in a generated password. */
static const char password_characters[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(){}[]:<>?,./";

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

    /* Initialize the pseudorandom generator using the current time. */
    srand( (unsigned int)time( NULL ) );

    generate_password( password, (size_t)password_length );
    printf( "Generated password: %s\n", password );

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

