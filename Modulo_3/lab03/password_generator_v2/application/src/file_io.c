/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 3
 * Author       : Tiago M. Dias (tiago.dias@isel.pt)
 * File         : file_io.c
 * Created      : 2026-11-16
 * Last modified: 2026-11-16
 * Description  : Functions for reading and writing binary files.
 */

#include <stdio.h>
#include <stdlib.h>

#include "file_io.h"

/* Maximum accepted input file size (1 MiB). */
#define MAX_FILE_SIZE (1024U * 1024U)

/*
 * Function   : write_binary_file
 * Description: Write a sequence of bytes to a binary file.
 * Inputs     : filename - path of the file to create or overwrite.
 *              data - buffer containing the bytes to write.
 *              data_length - number of bytes to write.
 * Outputs    : Returns 0 on success or -1 on error.
 */
int write_binary_file( const char *filename, const unsigned char *data,
                       size_t data_length )
{
    FILE *file;
    int result = 0;

    if ( filename == NULL || data == NULL || data_length == 0 ) {
        return -1;
    }

    file = fopen( filename, "wb" );
    if ( file == NULL ) {
        return -1;
    }

    if ( fwrite( data, 1, data_length, file ) != data_length ) {
        result = -1;
    }

    if ( fclose( file ) != 0 ) {
        result = -1;
    }

    return result;
}

/*
 * Function   : read_binary_file
 * Description: Read a binary file into a newly allocated buffer.
 * Inputs     : filename - path of the file to read.
 * Outputs    : data - allocated buffer, released by the caller using free().
 *              data_length - number of bytes read.
 *              Returns 0 on success or -1 on error.
 */
int read_binary_file( const char *filename, unsigned char **data,
                      size_t *data_length )
{
    FILE *file;
    unsigned char *buffer;
    long file_size;
    size_t bytes_read;
    int close_result;

    if ( filename == NULL || data == NULL || data_length == NULL ) {
        return -1;
    }

    *data = NULL;
    *data_length = 0;
    file = fopen( filename, "rb" );
    if ( file == NULL ) {
        return -1;
    }

    /* Determine the file size before allocating memory. */
    if ( fseek( file, 0, SEEK_END ) != 0 ) {
        fclose( file );
        return -1;
    }

    file_size = ftell( file );
    if ( file_size <= 0 || (unsigned long)file_size > MAX_FILE_SIZE ||
         fseek( file, 0, SEEK_SET ) != 0 ) {
        fclose( file );
        return -1;
    }

    buffer = malloc( (size_t)file_size );
    if ( buffer == NULL ) {
        fclose( file );
        return -1;
    }

    bytes_read = fread( buffer, 1, (size_t)file_size, file );
    close_result = fclose( file );
    if ( bytes_read != (size_t)file_size || close_result != 0 ) {
        free( buffer );
        return -1;
    }

    *data = buffer;
    *data_length = (size_t)file_size;
    return 0;
}
