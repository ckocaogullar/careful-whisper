#pragma once

#include <sgx_key_exchange.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * Define a structure to be used to transfer the Attestation Status 
 * from Server to client and include the Platform Info Blob in base16 
 * format as Message 4.
 *
 * The structure of Message 4 is not defined by SGX: it is up to the
 * service provider, and can include more than just the attestation
 * status and platform info blob.
 */

/*
 * This doesn't have to be binary. 
 */


int process_msg01(uint32_t msg0_extended_epid_group_id, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2, char **sigrl);
int process_msg3(sgx_ra_msg1_t *msg1, sgx_ra_msg3_t **msg3, size_t msg3_size, ra_msg4_t *msg4);
void generate_enclave_id();
int gossip_server();
int gossip_client();

#if defined(__cplusplus)
}
#endif