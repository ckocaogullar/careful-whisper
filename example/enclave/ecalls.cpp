#include "Enclave_t.h"
#include "enc.h"
#include "s_server.h"
#include "Log.h"
#include "ssl_conn_hdlr.h"

#ifdef __cplusplus
extern "C" {
#endif

int sgx_connect();
int sgx_accept();
void ssl_conn_init();
void ssl_conn_teardown();
void ssl_conn_handle(long int thread_id, thread_info_t *thread_info);

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

    return ssl_client(opt, headers, 2, buf, sizeof buf);
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