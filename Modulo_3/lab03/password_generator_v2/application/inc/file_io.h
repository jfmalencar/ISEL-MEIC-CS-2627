/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 3
 * Author       : Tiago M. Dias (tiago.dias@isel.pt)
 * File         : file_io.h
 * Created      : 2026-11-16
 * Last modified: 2026-11-16
 * Description  : Declarations of the binary file-handling functions.
 */

#ifndef FILE_IO_H
#define FILE_IO_H

#include <stddef.h>

int write_binary_file( const char *filename, const unsigned char *data,
                       size_t data_length );
int read_binary_file( const char *filename, unsigned char **data,
                      size_t *data_length );

#endif /* FILE_IO_H */
