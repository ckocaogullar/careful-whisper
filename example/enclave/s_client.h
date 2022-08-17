#pragma once

#include <sgx_key_exchange.h>

#if defined(__cplusplus)
extern "C" {
#endif

int process_msg01(uint32_t msg0_extended_epid_group_id, sgx_ra_msg1_t *msg1, char **sigrl);
#if defined(__cplusplus)
}
#endif