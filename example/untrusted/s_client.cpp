// This programme is written by Ceren Kocaogullar in July - Sept 2022 as part of Arm Veracruz project
// This is a fork of https://github.com/ffosilva/mbedtls-compat-sgx
// A considerable amount of code and logic is adopted from the Intel-provided remote attesation code https://github.com/intel/sgx-ra-sample.
// Explanation of this code can be found at: https://www.intel.com/content/www/us/en/developer/articles/code-sample/software-guard-extensions-remote-attestation-end-to-end-example.html

#include <iostream>
#include <stdio.h>
#include <sgx_urts.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <sgx_error.h>

#include "Enclave_u.h"
#include "Utils.h"
#include "msgio.h"
#include "hexutil.h"
#include "crypto.h"
#include "protocol.h"
#include <sys/stat.h>
#include "jsmn.h"

#include <unistd.h>
#include <time.h>
#include "benchmark.h"

using namespace std;

#define MODE_ATTEST 0x0

/* Global EID shared by multiple threads */
sgx_enclave_id_t eid = 0;

typedef struct config_struct
{
	char mode;
	uint32_t flags;
	sgx_spid_t spid;
	sgx_ec256_public_t pubkey;
	sgx_quote_nonce_t nonce;
	char *server;
	char *port;
} config_t;

// Options and modes coming from in the example code
#define MODE_ATTEST 0x0
#define MODE_EPID 0x1
#define MODE_QUOTE 0x2

#define OPT_PSE 0x01
#define OPT_NONCE 0x02
#define OPT_LINK 0x04
#define OPT_PUBKEY 0x08

#define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

/* Macros to set, clear, and get the mode and options */
#define SET_OPT(x, y) x |= y
#define CLEAR_OPT(x, y) x = x & ~y
#define OPT_ISSET(x, y) x &y

// char ids[2][10];
// strcpy(ids[0],"enclave_1");
// strcpy(ids[1], "enclave_2");

char* ids[] =
{
    (char*)("enclave_0"),
    (char*)("enclave_1"),
    (char*)("enclave_2"),

};

// Peers choose a random index and attempt to be the server at that index.
// One fails and one succeeds. They do the gossiping and attestation round with that configuration in the first peer round.
// Inn the seecond peer round, the roles change. Also, the peers talk at the (index + NUM_NODES)th port to avoid any connection errors,
// Seems that the connections are not cleaned up properly or fast enough to allow for another connection at the same port immediately.
char* msgio_ports[] =
{
    (char*)("7777"),
    (char*)("7778"),
    (char*)("7779"),
    (char*)("7780"),
    (char*)("7781"),
    (char*)("7782"),
};

char* gossip_ssl_ports[] =
{
    (char*)("4433"),
    (char*)("4434"),
	(char*)("4435"),
	(char*)("4436"),
    (char*)("4437"),
	(char*)("4438"),
};

char *msgio_port;
// Initialize chronometres for recording time
chronometre_t gossip_ch, full_attestation_ch, full_run_ch, generate_msg1_ch, generate_msg2_ch, generate_msg3_ch, generate_msg4_ch;

int do_verification(sgx_enclave_id_t eid);
int do_attestation(sgx_enclave_id_t eid, config_t *config);
int file_in_searchpath(const char *file, const char *search, char *fullpath,
					   size_t len);


sgx_status_t sgx_create_enclave_search(
	const char *filename,
	const int edebug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr);


int file_in_searchpath(const char *file, const char *search, char *fullpath,
					   size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if (search == NULL)
		return 0;
	if (strlen(search) == 0)
		return 0;

	str = strdup(search);
	if (str == NULL)
		return 0;

	p = strtok(str, ":");
	while (p != NULL)
	{
		size_t lp = strlen(p);

		if (lp)
		{

			strncpy(fullpath, p, len - 1);
			rem = (len - 1) - lp - 1;
			fullpath[len - 1] = 0;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if (stat(fullpath, &sb) == 0)
			{
				free(str);
				return 1;
			}
		}

		p = strtok(NULL, ":");
	}

	free(str);

	return 0;
}


sgx_status_t sgx_create_enclave_search(const char *filename, const int edebug,
									   sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
									   sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX]; /* includes NULL */

	/* Is filename an absolute path? */

	if (filename[0] == '/'){
		fprintf(stderr, "Found enclave in absolute path\n");
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
	}

	/* Is the enclave in the current working directory? */

	if (stat(filename, &sb) == 0){
		fprintf(stderr, "Found enclave in the current working directory\n");
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
	}

	/* Search the paths in LD_LBRARY_PATH */

	if (file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX)){
		fprintf(stderr, "Found enclave in LD_LIBRARY_PATH\n");
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	}

	/* Search the paths in DT_RUNPATH */

	if (file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX)){
		fprintf(stderr, "Found enclave in DT_RUNPATH\n");
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
	}

	/* Standard system library paths */

	if (file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX)){
		fprintf(stderr, "Found enclave in standard system library paths\n");
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
	}

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */
	fprintf(stderr, "Could not find enclave anywhere, don't know where else to look.\n");
	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}


// Verification part of the process normally happens in the service provider, not using any enclaves
// 
int do_verification(sgx_enclave_id_t eid)
{
	struct msg01_struct
	{
		uint32_t msg0_extended_epid_group_id;
		sgx_ra_msg1_t msg1;
	} * msg01;
	int rv;
	int *verif_result;
	MsgIO *msgio;
	sgx_ra_msg2_t msg2;
	sgx_ra_msg3_t *msg3;
	size_t msg3_size;
	attestation_status_t attestation_status; 
	sgx_platform_info_t platform_info;
	int msgio_failed = 1;

	while(msgio_failed){
		try
		{
			msgio = new MsgIO(NULL, msgio_port);
			msgio_failed = 0;
		}
		catch (...)
		{
			// exit(1);
			msgio_failed = 1;
		}
		printf("Msgio failed %d", msgio_failed);
	}


	while (msgio->server_loop())
	{
		fprintf(stderr, "Waiting for msg0||msg1\n");

		rv = msgio->read((void **)&msg01, NULL);
		if (rv == -1)
		{
			printf("system error reading msg0||msg1\n");
			return 0;
		}
		else if (rv == 0)
		{
			printf("protocol error reading msg0||msg1\n");
			return 0;
		}

		printf("Msg0 Details (from Verifier)\n");
		printf("msg0.extended_epid_group_id = %u\n",
				msg01->msg0_extended_epid_group_id);
		printf("\n");

		char *sigrl;
		verifier_step1(eid, verif_result, msg01->msg0_extended_epid_group_id, &msg01->msg1, &msg2, &sigrl);


		/* Send message 2 */

		/*
	 	* sgx_ra_msg2_t is a struct with a flexible array member at the
	 	* end (defined as uint8_t sig_rl[]). We could go to all the 
	 	* trouble of building a byte array large enough to hold the
	 	* entire struct and then cast it as (sgx_ra_msg2_t) but that's
	 	* a lot of work for no gain when we can just send the fixed 
	 	* portion and the array portion by hand.
	 	*/
	 	printf("Here is Msg2 before sending\n");
		
		printf("Msg2 Details\n");
		printf("msg2.g_b.gx      = %s\n",
			hexstring(&msg2.g_b.gx, sizeof(msg2.g_b.gx)));
		printf("msg2.g_b.gy      = %s\n",
			hexstring(&msg2.g_b.gy, sizeof(msg2.g_b.gy)));
		printf("msg2.spid        = %s\n",
			hexstring(&msg2.spid, sizeof(msg2.spid)));
		printf("msg2.quote_type  = %s\n",
			hexstring(&msg2.quote_type, sizeof(msg2.quote_type)));
		printf("msg2.kdf_id      = %s\n",
			hexstring(&msg2.kdf_id, sizeof(msg2.kdf_id)));
		printf("msg2.sign_gb_ga.x  = %s\n",
			hexstring((uint32_t *) msg2.sign_gb_ga.x, sizeof(msg2.sign_gb_ga.x)));
        printf("msg2.sign_gb_ga.y  = %s\n",
			hexstring((uint32_t *) msg2.sign_gb_ga.y, sizeof(msg2.sign_gb_ga.y)));
		printf("msg2.mac         = %s\n",
			hexstring(msg2.mac, sizeof(msg2.mac)));
		printf("msg2.sig_rl_size = %s\n",
			hexstring(&msg2.sig_rl_size, sizeof(msg2.sig_rl_size)));
    printf("\n");

		printf("Copy/Paste Msg2 Below to Client\n");

		msgio->send_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));

		msgio->send(sigrl, msg2.sig_rl_size);

	/*
	 * Read message 3
	 *
	 * CMACsmk(M) || M
	 *
	 * where
	 *
	 * M = ga || PS_SECURITY_PROPERTY || QUOTE
	 *
	 */

	printf("\n");
	printf("Reading Msg3\n");
	rv= msgio->read((void **) &msg3, &msg3_size);
	if ( rv == 0 ) {
		fprintf(stderr, "protocol error reading msg3\n");
		delete msgio;
		return 0;
	} else if ( rv == -1 ) {
		fprintf(stderr, "system error occurred while reading msg3\n");
		delete msgio;
		return 0;
	}

	printf("Msg3 on verifier, outside the enclave is %s\n", hexstring(msg3, msg3_size/2));
	ra_msg4_t msg4;
	verifier_step2(eid, verif_result, &msg01->msg1, &msg3, msg3_size, &msg4);

	// Send msg4
	printf("Copy/Paste Msg4 Below to Client\n"); 

	/* Serialize the members of the Msg4 structure independently */
	/* vs. the entire structure as one send_msg() */

	msgio->send_partial((void *)&msg4.status, sizeof(msg4.status));
	msgio->send(&msg4.platformInfoBlob, sizeof(msg4.platformInfoBlob));
	msgio->disconnect();

	return 1;
	}
}

// Attestation side of the process normally happens in the client 
// application and the enclave, therefore there is no real 
// need to change the existing RA code in sgx-ra-sample
int do_attestation(sgx_enclave_id_t eid, config_t *config)
{
	sgx_status_t status, sgxrv, pse_status;
	sgx_ra_msg1_t msg1;
	sgx_ra_msg2_t *msg2 = NULL;
	sgx_ra_msg3_t *msg3 = NULL;
	ra_msg4_t *msg4 = NULL;
	uint32_t msg0_extended_epid_group_id = 0;
	uint32_t msg3_sz;
	size_t msg4_sz = 0;
	uint32_t flags = config->flags;
	sgx_ra_context_t ra_ctx = 0xdeadbeef;
	int rv;
	MsgIO *msgio;
	int enclaveTrusted = NotTrusted; // Not Trusted
	int b_pse = OPT_ISSET(flags, OPT_PSE);
	int msgio_established_flag = 0;
	printf("Eid is %d\n", eid);
	printf("Msgio port is %s", msgio_port);

	while(msgio_established_flag == 0){
		
			try
			{
				msgio = new MsgIO(config->server, msgio_port);
				msgio_established_flag = 1;
			}
			catch (...)
			{
				// exit(1);
				printf("A Msgio error occured \n");
				msgio_established_flag = 1;
			}
		
	}


	/*
	 * WARNING! Normally, the public key would be hardcoded into the
	 * enclave, not passed in as a parameter. Hardcoding prevents
	 * the enclave using an unauthorized key.
	 *
	 * This is diagnostic/test application, however, so we have
	 * the flexibility of a dynamically assigned key.
	 */

	/* Executes an ECALL that runs sgx_ra_init() */

	if (OPT_ISSET(flags, OPT_PUBKEY))
	{

			fprintf(stderr, "+++ using supplied public key\n");
		status = enclave_ra_init(eid, &sgxrv, config->pubkey, b_pse,
								 &ra_ctx, &pse_status);
	}
	else
	{
			fprintf(stderr, "+++ using default public key\n");
		status = enclave_ra_init_def(eid, &sgxrv, b_pse, &ra_ctx,
									 &pse_status);
	}

	/* Did the ECALL succeed? */
	if (status != SGX_SUCCESS)
	{
		fprintf(stderr, "enclave_ra_init: %08x\n", status);
		delete msgio;
		return 1;
	}

	/* Did sgx_ra_init() succeed? */
	if (sgxrv != SGX_SUCCESS)
	{
		fprintf(stderr, "sgx_ra_init: %08x\n", sgxrv);
		delete msgio;
		return 1;
	}

	/* Generate msg0 */

	status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
	if (status != SGX_SUCCESS)
	{
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_get_extended_epid_group_id: %08x\n", status);
		delete msgio;
		return 1;
	}

		fprintf(stderr, "Msg0 Details (from Prover)\n");
		fprintf(stderr, "Extended Epid Group ID: ");
		print_hexstring(stderr, &msg0_extended_epid_group_id,
						sizeof(uint32_t));
		fprintf(stderr, "\n");
	

	/* Generate msg1 */

	status = sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);
	if (status != SGX_SUCCESS)
	{
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
		delete msgio;
		return 1;
	}

		fprintf(stderr, "Msg1 Details (from Prover)\n");
		fprintf(stderr, "msg1.g_a.gx = ");
		print_hexstring(stderr, msg1.g_a.gx, 32);
		fprintf(stderr, "\nmsg1.g_a.gy = ");
		print_hexstring(stderr, msg1.g_a.gy, 32);
		fprintf(stderr, "\nmsg1.gid    = ");
		print_hexstring(stderr, msg1.gid, 4);
		fprintf(stderr, "\n");
	

	/*
	 * Send msg0 and msg1 concatenated together (msg0||msg1). We do
	 * this for efficiency, to eliminate an additional round-trip
	 * between client and server. The assumption here is that most
	 * clients have the correct extended_epid_group_id so it's
	 * a waste to send msg0 separately when the probability of a
	 * rejection is astronomically small.
	 *
	 * If it /is/ rejected, then the client has only wasted a tiny
	 * amount of time generating keys that won't be used.
	 */


	fprintf(stderr, "Copy/Paste Msg0||Msg1 Below to SP\n");
	msgio->send_partial(&msg0_extended_epid_group_id,
						sizeof(msg0_extended_epid_group_id));
	msgio->send(&msg1, sizeof(msg1));

	fprintf(stderr, "Waiting for msg2 here.\n");

	/* Read msg2 
	 *
	 * msg2 is variable length b/c it includes the revocation list at
	 * the end. msg2 is malloc'd in readZ_msg do free it when done.
	 */

	rv= msgio->read((void **) &msg2, NULL);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg2\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg2\n");
		delete msgio;
		exit(1);
	}


		fprintf(stderr, "Msg2 Details\n");
		fprintf(stderr,   "msg2.g_b.gx      = ");
		print_hexstring(stderr, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		fprintf(stderr, "\nmsg2.g_b.gy      = ");
		print_hexstring(stderr, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		fprintf(stderr, "\nmsg2.spid        = ");
		print_hexstring(stderr, &msg2->spid, sizeof(msg2->spid));
		fprintf(stderr, "\nmsg2.quote_type  = ");
		print_hexstring(stderr, &msg2->quote_type, sizeof(msg2->quote_type));
		fprintf(stderr, "\nmsg2.kdf_id      = ");
		print_hexstring(stderr, &msg2->kdf_id, sizeof(msg2->kdf_id));
		fprintf(stderr, "\nmsg2.sign_ga_gb  = ");
		print_hexstring(stderr, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		fprintf(stderr, "\nmsg2.mac         = ");
		print_hexstring(stderr, &msg2->mac, sizeof(msg2->mac));
		fprintf(stderr, "\nmsg2.sig_rl_size = ");
		print_hexstring(stderr, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		fprintf(stderr, "\nmsg2.sig_rl      = ");
		print_hexstring(stderr, &msg2->sig_rl, msg2->sig_rl_size);
		fprintf(stderr, "\n");

		fprintf(stderr, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
		
	
	/* Process Msg2, Get Msg3  */
	/* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

	msg3 = NULL;

	status = sgx_ra_proc_msg2(ra_ctx, eid,
		sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, 
		sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
	    &msg3, &msg3_sz);

	free(msg2);

	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);

		delete msgio;
		return 1;
	} 

		fprintf(stderr, "+++ msg3_size = %u\n", msg3_sz);
	                          
		fprintf(stderr, "Msg3 Details\n");
		fprintf(stderr,   "msg3.mac         = ");
		print_hexstring(stderr, msg3->mac, sizeof(msg3->mac));
		fprintf(stderr, "\nmsg3.g_a.gx      = ");
		print_hexstring(stderr, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		fprintf(stderr, "\nmsg3.g_a.gy      = ");
		print_hexstring(stderr, msg3->g_a.gy, sizeof(msg3->g_a.gy));
		fprintf(stderr, "\nmsg3.quote       = ");
		print_hexstring(stderr, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		fprintf(stderr, "\n");	

	fprintf(stderr, "Copy/Paste Msg3 Below to SP\n");
	msgio->send(msg3, msg3_sz);


	if ( msg3 ) {
		free(msg3);
		msg3 = NULL;
	}

	/* Read Msg4 provided by Service Provider, then process */
        
	rv= msgio->read((void **)&msg4, &msg4_sz);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg4\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg4\n");
		delete msgio;
		exit(1);
	}

	printf("\nEnclave Trust Status from Service Provider\n");

	enclaveTrusted= msg4->status;
	if ( enclaveTrusted == Trusted ) {
		printf("Enclave TRUSTED\n");
	}
	else if ( enclaveTrusted == NotTrusted ) {
		printf("Enclave NOT TRUSTED\n");
	}
	else if ( enclaveTrusted == Trusted_ItsComplicated ) {
		// Trusted, but client may be untrusted in the future unless it
		// takes action.
	printf("Enclave Trust is TRUSTED and COMPLICATED. The client is out of date and\nmay not be trusted in the future depending on the service provider's  policy.\n");
	} else {
		// Not Trusted, but client may be able to take action to become
		// trusted.

		printf("Enclave Trust is NOT TRUSTED and COMPLICATED. The client is out of date.\n");
	}
	msgio->disconnect();
	return 1;
}

int main(int argc, char **argv)
{
	int ret;
	int opt;
	config_t config;
	sgx_launch_token_t token = {0};
	sgx_status_t status;
	sgx_enclave_id_t eid = 0;
	int updated = 0;
	int sgx_support;
	uint32_t i;
	EVP_PKEY *service_public_key = NULL;
	char flag_stdio = 0;

	memset(&config, 0, sizeof(config));
	config.mode = MODE_ATTEST;


		for (i = 0; i < 2; ++i)
		{
			int retry = 10;
			unsigned char ok = 0;
			uint64_t *np = (uint64_t *)&config.nonce;

			while (!ok && retry)
				ok = _rdrand64_step(&np[i]);
			if (ok == 0)
			{
				fprintf(stderr, "nonce: RDRAND underflow\n");
				exit(1);
			}
		}
		SET_OPT(config.flags, OPT_NONCE);

		SET_OPT(config.flags, OPT_PSE);
	
		SET_OPT(config.flags, OPT_LINK);


		// Set the server and the port
		config.server = strdup("localhost");
		config.port = msgio_port;

		// Launch the enclave
		status = sgx_create_enclave_search(ENCLAVE_NAME,
									   SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
		if (status != SGX_SUCCESS)
		{
			fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
					ENCLAVE_NAME, status);
			if (status == SGX_ERROR_ENCLAVE_FILE_ACCESS)
				fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
			return 1;
		}
		int gossip_ret;
		
		// Generate ID for the initiated enclave
	
		int returned;
		int encalve_id_flag = 0;
		int prover_verifier_flag = 1;
		// Denotes if the peer acted as the server or the client in the first peer round
		int server_first_flag = 0;
		// Counting the number of rounds made per peer, can be 2 maximum
		int peer_round = 0;
		int self_index;
		int port_index;
		char *gossip_port;
		srand ( time(NULL) );

	
		// Run the enclave functionality based on the input
	    while ((opt = getopt(argc, argv, "pvmi:n:")) != -1) {
    	    switch (opt) {
			// Optional ID value for the enclave
			case 'i':
				self_index = atoi(optarg);
				printf("ID provided as OPTARG %s\n", ids[self_index]);

				// Use the provided ID for the initiated enclave
				generate_enclave_id(eid, ids[self_index], strlen(ids[self_index]));
				encalve_id_flag = 1;
				break;
			// The enclave will act as a prover
        	case 'p': 
				// If ID is not provided as an input, generate random ID
				// if(!encalve_id_flag){
				// 	generate_enclave_id(eid, NULL, 0);
				// }
				// start_chronometre(&gossip_ch);
				// run_gossip_client(eid, gossip_ret);
				// stop_chronometre(&gossip_ch);
	
				// printf("\n ------------------ GOSSIPING FINISHED, STARTING ATTESTATION ------------------\n");
				
				// start_chronometre(&full_attestation_ch);
				// do_attestation(eid, &config);  
				// stop_chronometre(&full_attestation_ch);
				
				// printf("\n ------------------ ATTESTATION FINISHED ------------------\n");

				// run_gossip_client(eid, gossip_ret);


				printf("Time passed for gossiping %d\n", calc_time_passed(gossip_ch));	
				printf("Time passed for attestation %d\n", calc_time_passed(full_attestation_ch));	

				break;
			// The enclave will act as a verifier
        	case 'v': 
				// If ID is not provided as an input, generate random ID
				// if(!encalve_id_flag){
				// 	generate_enclave_id(eid, NULL, 0);
				// }
				// start_chronometre(&gossip_ch);
				// run_gossip_server(eid, gossip_ret);
				// stop_chronometre(&gossip_ch);
	
				// printf("\n ------------------ GOSSIPING FINISHED, STARTING VERIFICATION ------------------\n");

				// start_chronometre(&full_attestation_ch);
				// do_verification(eid);
				// stop_chronometre(&full_attestation_ch);
				
				// printf("\n ------------------ VERIFICATION FINISHED ------------------\n");

				// run_gossip_server(eid, gossip_ret);


				printf("Time passed for gossiping is %d\n", calc_time_passed(gossip_ch));	
				printf("Time passed for attestation %d\n", calc_time_passed(full_attestation_ch));	

				break;
			case 'm':
				if(!encalve_id_flag){
					generate_enclave_id(eid, NULL, 0);
				}

				// Pick a random index to decide on the port
				port_index = rand() % (NUM_NODES-1);
				printf("Port index is %d", port_index);
				msgio_port = msgio_ports[port_index];
				gossip_port = gossip_ssl_ports[port_index];
				
				while(gossip_ret<NUM_NODES){

				printf("\n ------------------ GOSSIPING STARTING AS SERVER, PEER ROUND %d------------------\n", peer_round);

					if(prover_verifier_flag == 1){
						start_chronometre(&full_run_ch);
						start_chronometre(&gossip_ch);
						run_gossip_server(eid, &gossip_ret, gossip_port);
						stop_chronometre(&gossip_ch);
						prover_verifier_flag = 0;
						printf("Setting prover verifier flag to %d", prover_verifier_flag);

					}

					
					// If run_gossip_server returns an error, try being the client
					if(gossip_ret == -1 || server_first_flag == 1){
				printf("\n ------------------ GOSSIPING STARTING AS CLIENT, PEER ROUND %d------------------\n", peer_round);
						printf("Trying with the client side now\n");
						start_chronometre(&gossip_ch);
						run_gossip_client(eid, &gossip_ret, gossip_port);
						stop_chronometre(&gossip_ch);
						prover_verifier_flag = 1;
						printf("Setting prover verifier flag to %d", prover_verifier_flag);

					} 

					printf("Prover verifier flag set to %d", prover_verifier_flag);

					printf("Number of trusted nodes is %d, NUM_NODES is %d", gossip_ret, NUM_NODES);
					
					// If all nodes are collected
					if(gossip_ret == NUM_NODES){
						stop_chronometre(&full_run_ch);
						printf("Know all the nodes now, it took %d\n", calc_time_passed(full_run_ch));
						break;
					}



				printf("\n ------------------ GOSSIPING FINISHED, STARTING ATTESTATION ------------------\n");
					

					if(prover_verifier_flag == 0){
				printf("\n ------------------ ATTESTATION STARTING AS VERIFIER------------------\n");

						printf("Acting as the verifier\n");
						start_chronometre(&full_attestation_ch);
						do_verification(eid);
						stop_chronometre(&full_attestation_ch);
						server_first_flag = 1;

					}
					else if (prover_verifier_flag == 1)
					{
				printf("\n ------------------ ATTESTATION STARTING AS PROVER------------------\n");

						printf("Acting as the prover\n");
						start_chronometre(&full_attestation_ch);
						do_attestation(eid, &config);  
						stop_chronometre(&full_attestation_ch);
					}
				printf("\n ------------------ ATTESTATION FINISHED ------------------\n");

				
				// Prepare for the next peer round
				peer_round++;
				port_index += NUM_NODES;
				msgio_port = msgio_ports[port_index];
				gossip_port = gossip_ssl_ports[port_index];

				// If the peers have finished their round, switch to another peer
				if(peer_round == 2){
				printf("\n ------------------ ROUND FINISHED ------------------\n");
					port_index = rand() % (NUM_NODES-1);
					msgio_port = msgio_ports[port_index];
					gossip_port = gossip_ssl_ports[port_index];
					prover_verifier_flag = 1;
					peer_round = 0;
					server_first_flag = 0;
					printf("Port index is %d", port_index);

				}
				}
				
				break;
	        default:
    	        fprintf(stderr, "Usage: %s [-p] for prover, [-v] for verifier.\n", argv[0]);
        	    exit(EXIT_FAILURE);
        }
    }

	return 0;



exit:
	sgx_destroy_enclave(eid);
	printf("Info: all enclave closed successfully.\n");
	return 0;
}
