#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_generate_password_t {
    int ms_retval;
    size_t ms_len;
    char* ms_buff;
    size_t ms_buff_size;
} ms_ecall_generate_password_t;

static const struct {
    size_t nr_ocall;
    void * table[1];
} ocall_table_enclave = {
    0,
    { NULL },
};
sgx_status_t ecall_generate_password(sgx_enclave_id_t eid, int* retval, size_t len, char* buff, size_t buff_size)
{
    sgx_status_t status;
    ms_ecall_generate_password_t ms;
    ms.ms_len = len;
    ms.ms_buff = buff;
    ms.ms_buff_size = buff_size;
    status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
    if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
    return status;
}