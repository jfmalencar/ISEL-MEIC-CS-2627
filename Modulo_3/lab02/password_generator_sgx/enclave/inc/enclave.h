/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 2
 * Authors      : Jessé Ferreira de Moura Alencar (A51745)
 *                Rodrigo Dos Ramos Pais Henriques Vitorino (A49448)
 * File         : enclave.h
 * Created      : 2026-11-09
 * Last modified: 2026-11-21
 * Description  : Password length limits and functions available inside the enclave.
 */

#ifndef ENCLAVE_H
#define ENCLAVE_H

#include <stddef.h>   
#include <stdlib.h>

#define PASSWORD_MIN_LENGTH      8
#define PASSWORD_MAX_LENGTH    100

/*
 * Build a password using the SGX trusted random number generator.
 * The caller must provide password_length + 1 bytes.
 * Returns 0 on success or -1 if random generation fails.
 */
int generate_password( char *password, size_t password_length );


#endif /* ENCLAVE_H */
