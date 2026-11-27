/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 2
 * Authors      : Jessé Ferreira de Moura Alencar (A51745)
 *                Rodrigo Dos Ramos Pais Henriques Vitorino (A49448)
 * File         : app.h
 * Created      : 2026-11-09
 * Last modified: 2026-11-21
 * Description  : Password length definitions and function declarations.
 */

#ifndef APP_H
#define APP_H

#include <stddef.h>

#define ENCLAVE_FILENAME "enclave.signed.so"

#define PASSWORD_MIN_LENGTH      8
#define PASSWORD_MAX_LENGTH    100
#define PASSWORD_DEFAULT_LENGTH 16

void generate_password( char *password, size_t password_length );

#endif /* APP_H */
