/*
 * Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
 * Project      : Cybersecurity (Module 3 - Hardware Security): Lab 2
 * Author       : Tiago M. Dias (tiago.dias@isel.pt)
 * File         : sgx_utils.h
 * Created      : 2026-11-09
 * Last modified: 2026-11-09
 * Description  : Declarations of the SGX runtime error-reporting helper.
 */

#ifndef SGX_UTILS_H
#define SGX_UTILS_H

#include <sgx_urts.h>

/* Print the meaning of an SGX runtime error to standard error. */
void print_sgx_error( sgx_status_t status );

#endif /* SGX_UTILS_H */
