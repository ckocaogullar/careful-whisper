#include "Enclave_t.h"
#include "enc.h"
#include "s_server.h"
#include "Log.h"
#include "ssl_conn_hdlr.h"
#include "sgx_key_exchange.h"
#include "s_client.h"

#ifdef __cplusplus
extern "C" {
#endif

static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

int sgx_connect();
int sgx_accept();
void ssl_conn_init();
void ssl_conn_teardown();
void ssl_conn_handle(long int thread_id, thread_info_t *thread_info);
int verifier_step1(uint32_t msg0_extended_epid_group_id, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2, char **sigrl);
int verifier_step2(sgx_ra_msg1_t *msg1, sgx_ra_msg3_t **msg3, size_t msg3_size, ra_msg4_t *msg4);
sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t *ctx, sgx_status_t *pse_status);
sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse, sgx_ra_context_t *ctx, sgx_status_t *pse_status);
sgx_status_t enclave_ra_close(sgx_ra_context_t ctx);

#ifdef __cplusplus
}
#endif

int sgx_connect()
{
    client_opt_t opt;
    unsigned char buf[1024];
    client_opt_init(&opt);
    opt.debug_level = 1;
    opt.server_addr = "api.trustedservices.intel.com";
    opt.request_page = "/sgx/dev/attestation/v4/sigrl/00000c1f HTTP/1.1";
    char* headers[2]; 
    headers[0] = "Host: api.trustedservices.intel.com";
    headers[1] = "Ocp-Apim-Subscription-Key: 2f4641eb3f334703adafa46c35556505";

    return ssl_client(opt, (request_t) get, headers, 2, NULL, buf, sizeof buf);
}

int sgx_accept()
{
    return ssl_server();
}

TLSConnectionHandler* connectionHandler;

void ssl_conn_init(void) {
  connectionHandler = new TLSConnectionHandler();
}

void ssl_conn_handle(long int thread_id, thread_info_t* thread_info) {
  connectionHandler->handle(thread_id, thread_info);
}

void ssl_conn_teardown(void) {
  delete connectionHandler;
}

int verifier_step1(uint32_t msg0_extended_epid_group_id, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2, char **sigrl){
  return process_msg01(msg0_extended_epid_group_id, msg1, msg2, sigrl);
}

int verifier_step2(sgx_ra_msg1_t *msg1, sgx_ra_msg3_t **msg3, size_t msg3_size, ra_msg4_t *msg4){
  return process_msg3(msg1, msg3, msg3_size, msg4);
}

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

	ra_status= sgx_ra_init(&key, 0, ctx);

	return ra_status;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}

sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t *ctx,
	sgx_status_t *pse_status)
{
	return enclave_ra_init(def_service_public_key, b_pse, ctx, pse_status);
}