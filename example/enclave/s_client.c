/*
 *  SSL client with certificate authentication
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include "Enclave_t.h"
#include "enc.h"
#include "Log.h"
#include "pprint.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#if !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) || \
    !defined(MBEDTLS_CTR_DRBG_C)
#else



#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include "hexstring.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_quote.h"
#include "picohttpparser/picohttpparser.h"


#include <stdio.h>
#include <stdlib.h>
#include "string.h"

// Modify the following setting values with the correct values
#define SPID "347A02ABAE509A6E43E376C7250FAE99"
#define IAS_PRIMARY_SUBSCRIPTION_KEY "a86c71cb05af4c33a7bf9ec34e8ccd64"
#define IAS_SECONDARY_SUBSCRIPTION_KEY "bc86eeb48ae144d0926d98f74228b8e2"
#define IAS_REPORT_SIGNING_CA_FILE "Intel_SGX_Attestation_RootCA.pem"

// Modify these for a different policy file, if needed.
#define MRSIGNER "bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd"
#define PRODID "0"
#define MIN_ISVSVN "1"
#define ALLOW_DEBUG "1"

// Initializing the SMK here, since it will be used in multiple
// message processing functions
sgx_cmac_128bit_tag_t smk;


static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};


#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
#define USAGE_IO \
    "    ca_file=%%s          The single file containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded)\n" \
    "    ca_path=%%s          The path containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded) (overrides ca_file)\n" \
    "    crt_file=%%s         Your own cert and chain (in bottom to top order, top may be omitted)\n" \
    "                        default: \"\" (pre-loaded)\n" \
    "    key_file=%%s         default: \"\" (pre-loaded)\n"
#else
#define USAGE_IO \
    "    No file operations available (MBEDTLS_FS_IO not defined)\n"
#endif /* MBEDTLS_FS_IO */
#else
#define USAGE_IO ""
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
#define USAGE_PSK                                                   \
    "    psk=%%s              default: \"\" (in hex, without 0x)\n" \
    "    psk_identity=%%s     default: \"Client_identity\"\n"
#else
#define USAGE_PSK ""
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
#define USAGE_TICKETS                                       \
    "    tickets=%%d          default: 1 (enabled)\n"
#else
#define USAGE_TICKETS ""
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
#define USAGE_TRUNC_HMAC                                    \
    "    trunc_hmac=%%d       default: library default\n"
#else
#define USAGE_TRUNC_HMAC ""
#endif /* MBEDTLS_SSL_TRUNCATED_HMAC */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#define USAGE_MAX_FRAG_LEN                                      \
    "    max_frag_len=%%d     default: 16384 (tls default)\n"   \
    "                        options: 512, 1024, 2048, 4096\n"
#else
#define USAGE_MAX_FRAG_LEN ""
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
#define USAGE_RECSPLIT \
    "    recsplit=0/1        default: (library default: on)\n"
#else
#define USAGE_RECSPLIT
#endif

#if defined(MBEDTLS_DHM_C)
#define USAGE_DHMLEN \
    "    dhmlen=%%d           default: (library default: 1024 bits)\n"
#else
#define USAGE_DHMLEN
#endif

#if defined(MBEDTLS_SSL_ALPN)
#define USAGE_ALPN \
    "    alpn=%%s             default: \"\" (disabled)\n"   \
    "                        example: spdy/1,http/1.1\n"
#else
#define USAGE_ALPN ""
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
#define USAGE_DTLS \
    "    dtls=%%d             default: 0 (TLS)\n"                           \
    "    hs_timeout=%%d-%%d    default: (library default: 1000-60000)\n"    \
    "                        range of DTLS handshake timeouts in millisecs\n"
#else
#define USAGE_DTLS ""
#endif

#if defined(MBEDTLS_SSL_FALLBACK_SCSV)
#define USAGE_FALLBACK \
    "    fallback=0/1        default: (library default: off)\n"
#else
#define USAGE_FALLBACK ""
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
#define USAGE_EMS \
    "    extended_ms=0/1     default: (library default: on)\n"
#else
#define USAGE_EMS ""
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
#define USAGE_ETM \
    "    etm=0/1             default: (library default: on)\n"
#else
#define USAGE_ETM ""
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
#define USAGE_RENEGO \
    "    renegotiation=%%d    default: 0 (disabled)\n"      \
    "    renegotiate=%%d      default: 0 (disabled)\n"
#else
#define USAGE_RENEGO ""
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#define USAGE_ECJPAKE \
    "    ecjpake_pw=%%s       default: none (disabled)\n"
#else
#define USAGE_ECJPAKE ""
#endif

#define USAGE \
    "\n usage: ssl_client2 param=<>...\n"                   \
    "\n acceptable parameters:\n"                           \
    "    server_name=%%s      default: localhost\n"         \
    "    server_addr=%%s      default: given by name\n"     \
    "    server_port=%%d      default: 4433\n"              \
    "    request_page=%%s     default: \".\"\n"             \
    "    request_size=%%d     default: about 34 (basic request)\n" \
    "                        (minimum: 0, max: 16384)\n" \
    "    debug_level=%%d      default: 0 (disabled)\n"      \
    "    nbio=%%d             default: 0 (blocking I/O)\n"  \
    "                        options: 1 (non-blocking), 2 (added delays)\n" \
    "    read_timeout=%%d     default: 0 ms (no timeout)\n"    \
    "    max_resend=%%d       default: 0 (no resend on timeout)\n" \
    "\n"                                                    \
    USAGE_DTLS                                              \
    "\n"                                                    \
    "    auth_mode=%%s        default: (library default: none)\n"      \
    "                        options: none, optional, required\n" \
    USAGE_IO                                                \
    "\n"                                                    \
    USAGE_PSK                                               \
    USAGE_ECJPAKE                                           \
    "\n"                                                    \
    "    allow_legacy=%%d     default: (library default: no)\n"      \
    USAGE_RENEGO                                            \
    "    exchanges=%%d        default: 1\n"                 \
    "    reconnect=%%d        default: 0 (disabled)\n"      \
    "    reco_delay=%%d       default: 0 seconds\n"         \
    "    reconnect_hard=%%d   default: 0 (disabled)\n"      \
    USAGE_TICKETS                                           \
    USAGE_MAX_FRAG_LEN                                      \
    USAGE_TRUNC_HMAC                                        \
    USAGE_ALPN                                              \
    USAGE_FALLBACK                                          \
    USAGE_EMS                                               \
    USAGE_ETM                                               \
    USAGE_RECSPLIT                                          \
    USAGE_DHMLEN                                            \
    "\n"                                                    \
    "    arc4=%%d             default: (library default: 0)\n" \
    "    min_version=%%s      default: (library default: tls1)\n"       \
    "    max_version=%%s      default: (library default: tls1_2)\n"     \
    "    force_version=%%s    default: \"\" (none)\n"       \
    "                        options: ssl3, tls1, tls1_1, tls1_2, dtls1, dtls1_2\n" \
    "\n"                                                    \
    "    force_ciphersuite=<name>    default: all enabled\n"\
    " acceptable ciphersuite names:\n"

/*
 * global options
 */



static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    const char *p, *basename;
    (void)(ctx);

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;

    mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str );
}

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */
static int my_recv( void *ctx, unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }

    ret = mbedtls_net_recv( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_READ )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

static int my_send( void *ctx, const unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_WRITE );
    }

    ret = mbedtls_net_send( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/*
 * Enabled if debug_level > 1 in code below
 */
static int my_verify( void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags )
{
    char buf[1024];
    ((void) data);

    mbedtls_printf( "\nVerify requested for (Depth %d):\n", depth );
    mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt );
    mbedtls_printf( "%s", buf );

    if ( ( *flags ) == 0 )
        mbedtls_printf( "  This certificate has no flags\n" );
    else
    {
        mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "  ! ", *flags );
        mbedtls_printf( "%s\n", buf );
    }

    return( 0 );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

uint8_t* datahex(char* string) {

    if(string == NULL) 
       return NULL;

    size_t slength = strlen(string);
    if((slength % 2) != 0) // must be even
       return NULL;

    size_t dlength = slength / 2;

    uint8_t* data = malloc(dlength);
    memset(data, 0, dlength);

    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if(c >= '0' && c <= '9')
          value = (c - '0');
        else if (c >= 'A' && c <= 'F') 
          value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
          value = (10 + (c - 'a'));
        else {
          free(data);
          return NULL;
        }

        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}


int ssl_client(client_opt_t opt, request_t req_type, char* headers[], int n_header, char* body, unsigned char* output, int length)
{
    mbedtls_printf("SSL Client called\n");
         
    int ret = 0, len, tail_len, i, written, frags, retry_left;
    mbedtls_net_context server_fd;
    unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char psk[MBEDTLS_PSK_MAX_LEN];
    size_t psk_len = 0;
#endif
#if defined(MBEDTLS_SSL_ALPN)
    const char *alpn_list[10];
#endif
    const char *pers = "ssl_client2";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ssl_session saved_session;
#if defined(MBEDTLS_TIMING_C)
    mbedtls_timing_delay_context timer;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    uint32_t flags;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
#endif
    char *p;
    const int *list;

    /*
     * Make sure memory references are valid.
     */
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    memset( &saved_session, 0, sizeof( mbedtls_ssl_session ) );
    mbedtls_ctr_drbg_init( &ctr_drbg );
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &clicert );
    mbedtls_pk_init( &pkey );
#endif
#if defined(MBEDTLS_SSL_ALPN)
    memset( (void * ) alpn_list, 0, sizeof( alpn_list ) );
#endif

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( opt.debug_level );
#endif

    if( opt.force_ciphersuite[0] > 0 )
    {
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
        ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( opt.force_ciphersuite[0] );

        if( opt.max_version != -1 &&
            ciphersuite_info->min_minor_ver > opt.max_version )
        {
            mbedtls_printf("forced ciphersuite not allowed with this protocol version\n");
            ret = 2;
            goto usage;
        }
        if( opt.min_version != -1 &&
            ciphersuite_info->max_minor_ver < opt.min_version )
        {
            mbedtls_printf("forced ciphersuite not allowed with this protocol version\n");
            ret = 2;
            goto usage;
        }

        /* If the server selects a version that's not supported by
         * this suite, then there will be no common ciphersuite... */
        if( opt.max_version == -1 ||
            opt.max_version > ciphersuite_info->max_minor_ver )
        {
            opt.max_version = ciphersuite_info->max_minor_ver;
        }
        if( opt.min_version < ciphersuite_info->min_minor_ver )
        {
            opt.min_version = ciphersuite_info->min_minor_ver;
            /* DTLS starts with TLS 1.1 */
            if( opt.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
                opt.min_version < MBEDTLS_SSL_MINOR_VERSION_2 )
                opt.min_version = MBEDTLS_SSL_MINOR_VERSION_2;
        }

        /* Enable RC4 if needed and not explicitly disabled */
        if( ciphersuite_info->cipher == MBEDTLS_CIPHER_ARC4_128 )
        {
            if( opt.arc4 == MBEDTLS_SSL_ARC4_DISABLED )
            {
                mbedtls_printf("forced RC4 ciphersuite with RC4 disabled\n");
                ret = 2;
                goto usage;
            }

            opt.arc4 = MBEDTLS_SSL_ARC4_ENABLED;
        }
    }

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    /*
     * Unhexify the pre-shared key if any is given
     */
    if( strlen( opt.psk ) )
    {
        unsigned char c;
        size_t j;

        if( strlen( opt.psk ) % 2 != 0 )
        {
            mbedtls_printf("pre-shared key not valid hex\n");
            goto exit;
        }

        psk_len = strlen( opt.psk ) / 2;

        for( j = 0; j < strlen( opt.psk ); j += 2 )
        {
            c = opt.psk[j];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                mbedtls_printf("pre-shared key not valid hex\n");
                goto exit;
            }
            psk[ j / 2 ] = c << 4;

            c = opt.psk[j + 1];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                mbedtls_printf("pre-shared key not valid hex\n");
                goto exit;
            }
            psk[ j / 2 ] |= c;
        }
    }
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_SSL_ALPN)
    if( opt.alpn_string != NULL )
    {
        p = (char *) opt.alpn_string;
        i = 0;

        /* Leave room for a final NULL in alpn_list */
        while( i < (int) sizeof alpn_list - 1 && *p != '\0' )
        {
            alpn_list[i++] = p;

            /* Terminate the current string and move on to next one */
            while( *p != ',' && *p != '\0' )
                p++;
            if( *p == ',' )
                *p++ = '\0';
        }
    }
#endif /* MBEDTLS_SSL_ALPN */

    // XXX starting here!
    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_printf("Seeding the random number generator...\n" );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        LL_CRITICAL(" mbedtls_ctr_drbg_seed returned -%#x", -ret);
        goto exit;
    }
    
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    /*
     * 1.1. Load the trusted CA
     */
    mbedtls_printf( "Loading the CA root certificate\n");

#if defined(MBEDTLS_FS_IO)
    if( strlen( opt.ca_path ) )
        if( strcmp( opt.ca_path, "none" ) == 0 )
            ret = 0;
        else
            ret = mbedtls_x509_crt_parse_path( &cacert, opt.ca_path );
    else if( strlen( opt.ca_file ) )
        if( strcmp( opt.ca_file, "none" ) == 0 )
            ret = 0;
        else
            ret = mbedtls_x509_crt_parse_file( &cacert, opt.ca_file );
    else
#endif
    // load trusted crts

#include "ca_bundle.h"
    
  
  ret = mbedtls_x509_crt_parse(&cacert,
                               (const unsigned char *) mozilla_ca_bundle,
                               sizeof mozilla_ca_bundle);
  if (ret < 0) {
    LL_CRITICAL("  mbedtls_x509_crt_parse returned -%#x", -ret);
    goto exit;
  }

  if (ret != 0) {
    LL_CRITICAL("  mbedtls_pk_parse_key returned -%#x", -ret);
    goto exit;
  }

#endif /* MBEDTLS_X509_CRT_PARSE_C */

    /*
     * 2. Start the connection
     */
    
    if( opt.server_addr == NULL)
        opt.server_addr = opt.server_name;

    mbedtls_printf("connecting to %s:%s:%s...\n",
            opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ? "TCP" : "UDP",
            opt.server_addr, opt.server_port );

    if( ( ret = mbedtls_net_connect( &server_fd, opt.server_addr, opt.server_port,
                             opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ?
                             MBEDTLS_NET_PROTO_TCP : MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
        LL_CRITICAL( " mbedtls_net_connect returned -%#x", -ret );
        goto exit;
    }

    if( opt.nbio > 0 )
        ret = mbedtls_net_set_nonblock( &server_fd );
    else
        ret = mbedtls_net_set_block( &server_fd );
    if( ret != 0 )
    {
        LL_CRITICAL( " net_set_(non)block() returned -%#x", -ret );
        goto exit;
    }

    /*
     * 3. Setup stuff
     */
    mbedtls_printf( "Setting up the SSL/TLS structure...\n" );
    
    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    opt.transport,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        LL_CRITICAL( "mbedtls_ssl_config_defaults returned -%#x", -ret );
        goto exit;
    }
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( opt.debug_level > 0 ){
        mbedtls_ssl_conf_verify( &conf, my_verify, NULL );
    }
#endif

    if( opt.auth_mode != DFL_AUTH_MODE )
        mbedtls_ssl_conf_authmode( &conf, opt.auth_mode );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( opt.hs_to_min != DFL_HS_TO_MIN || opt.hs_to_max != DFL_HS_TO_MAX )
        mbedtls_ssl_conf_handshake_timeout( &conf, opt.hs_to_min, opt.hs_to_max );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    if( ( ret = mbedtls_ssl_conf_max_frag_len( &conf, opt.mfl_code ) ) != 0 )
    {
        mbedtls_printf( "  mbedtls_ssl_conf_max_frag_len returned %d\n\n", ret );
        goto exit;
    }
#endif

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    if( opt.trunc_hmac != DFL_TRUNC_HMAC )
        mbedtls_ssl_conf_truncated_hmac( &conf, opt.trunc_hmac );
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    if( opt.extended_ms != DFL_EXTENDED_MS )
        mbedtls_ssl_conf_extended_master_secret( &conf, opt.extended_ms );
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    if( opt.etm != DFL_ETM )
        mbedtls_ssl_conf_encrypt_then_mac( &conf, opt.etm );
#endif

#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    if( opt.recsplit != DFL_RECSPLIT )
        mbedtls_ssl_conf_cbc_record_splitting( &conf, opt.recsplit
                                    ? MBEDTLS_SSL_CBC_RECORD_SPLITTING_ENABLED
                                    : MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED );
#endif

#if defined(MBEDTLS_DHM_C)
    if( opt.dhmlen != DFL_DHMLEN )
        mbedtls_ssl_conf_dhm_min_bitlen( &conf, opt.dhmlen );
#endif

#if defined(MBEDTLS_SSL_ALPN)
    if( opt.alpn_string != NULL )
        if( ( ret = mbedtls_ssl_conf_alpn_protocols( &conf, alpn_list ) ) != 0 )
        {
            mbedtls_printf( "  mbedtls_ssl_conf_alpn_protocols returned %d\n\n", ret );
            goto exit;
        }
#endif

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, NULL );

    mbedtls_ssl_conf_read_timeout( &conf, opt.read_timeout );

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_conf_session_tickets( &conf, opt.tickets );
#endif

    if( opt.force_ciphersuite[0] != DFL_FORCE_CIPHER )
        mbedtls_ssl_conf_ciphersuites( &conf, opt.force_ciphersuite );

#if defined(MBEDTLS_ARC4_C)
    if( opt.arc4 != DFL_ARC4 )
        mbedtls_ssl_conf_arc4_support( &conf, opt.arc4 );
#endif

    if( opt.allow_legacy != DFL_ALLOW_LEGACY )
        mbedtls_ssl_conf_legacy_renegotiation( &conf, opt.allow_legacy );
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation( &conf, opt.renegotiation );
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( strcmp( opt.ca_path, "none" ) != 0 &&
        strcmp( opt.ca_file, "none" ) != 0 )
    {
        mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    }
    if( strcmp( opt.crt_file, "none" ) != 0 &&
        strcmp( opt.key_file, "none" ) != 0 )
    {
        if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &clicert, &pkey ) ) != 0 )
        {
            mbedtls_printf( "  mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
            goto exit;
        }
    }
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    if( ( ret = mbedtls_ssl_conf_psk( &conf, psk, psk_len,
                             (const unsigned char *) opt.psk_identity,
                             strlen( opt.psk_identity ) ) ) != 0 )
    {
        mbedtls_printf( "  mbedtls_ssl_conf_psk returned %d\n\n", ret );
        goto exit;
    }
#endif

    if( opt.min_version != DFL_MIN_VERSION )
        mbedtls_ssl_conf_min_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.min_version );

    if( opt.max_version != DFL_MAX_VERSION )
        mbedtls_ssl_conf_max_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.max_version );

#if defined(MBEDTLS_SSL_FALLBACK_SCSV)
    if( opt.fallback != DFL_FALLBACK )
        mbedtls_ssl_conf_fallback( &conf, opt.fallback );
#endif

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        LL_CRITICAL("mbedtls_ssl_setup returned -%#x", -ret );
        goto exit;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( ( ret = mbedtls_ssl_set_hostname( &ssl, opt.server_name ) ) != 0 )
    {
        LL_CRITICAL("mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    if( opt.ecjpake_pw != DFL_ECJPAKE_PW )
    {
        if( ( ret = mbedtls_ssl_set_hs_ecjpake_password( &ssl,
                        (const unsigned char *) opt.ecjpake_pw,
                                        strlen( opt.ecjpake_pw ) ) ) != 0 )
        {
            mbedtls_printf( "  mbedtls_ssl_set_hs_ecjpake_password returned %d\n\n", ret );
            goto exit;
        }
    }
#endif

    if( opt.nbio == 2 )
        mbedtls_ssl_set_bio( &ssl, &server_fd, my_send, my_recv, NULL );
    else
        mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
                             opt.nbio == 0 ? mbedtls_net_recv_timeout : NULL );

#if defined(MBEDTLS_TIMING_C)
    mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
                                            mbedtls_timing_get_delay );
#endif

    /*
     * 4. Handshake
     */
    mbedtls_printf( "Performing the SSL/TLS handshake\n" );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {   
            LL_CRITICAL( "mbedtls_ssl_handshake returned -%#x", -ret );
            if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED )
                LL_CRITICAL(
                    "Unable to verify the server's certificate. "
                    "Either it is invalid,"
                    "or you didn't set ca_file or ca_path "
                    "to an appropriate value."
                    "Alternatively, you may want to use "
                    "auth_mode=optional for testing purposes." );
            goto exit;
        }
    }

    mbedtls_printf( "Hand shake succeeds: [%s, %s]\n",
            mbedtls_ssl_get_version( &ssl ), mbedtls_ssl_get_ciphersuite( &ssl ) );

    if( ( ret = mbedtls_ssl_get_record_expansion( &ssl ) ) >= 0 )
        LL_DEBUG( "Record expansion is [%d]", ret );
    else
        LL_DEBUG( "Record expansion is [unknown (compression)]" );

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    mbedtls_printf( "Maximum fragment length is [%u]\n",
                    (unsigned int) mbedtls_ssl_get_max_frag_len( &ssl ) );
#endif

#if defined(MBEDTLS_SSL_ALPN)
    if( opt.alpn_string != NULL )
    {
        const char *alp = mbedtls_ssl_get_alpn_protocol( &ssl );
        mbedtls_printf( "    [ Application Layer Protocol is %s ]\n",
                alp ? alp : "(none)" );
    }
#endif

    if( opt.reconnect != 0 )
    {
        mbedtls_printf("  . Saving session for reuse...\n" );

        if( ( ret = mbedtls_ssl_get_session( &ssl, &saved_session ) ) != 0 )
        {
            LL_CRITICAL("mbedtls_ssl_get_session returned -%#x", -ret );
            goto exit;
        }

        mbedtls_printf("ok");
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf( "Verifying peer X.509 certificate...\n" );

    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        mbedtls_printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        mbedtls_printf( "%s\n", vrfy_buf );
    }
    else
        mbedtls_printf("X.509 Verifies\n");

    if( mbedtls_ssl_get_peer_cert( &ssl ) != NULL )
    {
        if (opt.debug_level > 0)
        {
            LL_DEBUG( "Peer certificate information");
            mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "|-", mbedtls_ssl_get_peer_cert( &ssl ) );
            mbedtls_printf("%s\n", buf);   
        }

    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( opt.renegotiate )
    {
        /*
         * Perform renegotiation (this must be done when the server is waiting
         * for input from our side).
         */
        mbedtls_printf( "  . Performing renegotiation..." );
        while( ( ret = mbedtls_ssl_renegotiate( &ssl ) ) != 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( "  mbedtls_ssl_renegotiate returned %d\n\n", ret );
                goto exit;
            }
        }
        mbedtls_printf( " ok\n" );
    }
#endif /* MBEDTLS_SSL_RENEGOTIATION */

    /*
     * 6. Write the GET request
     */
    retry_left = opt.max_resend;

send_request:
    mbedtls_printf("Sending a request\n");
    if (req_type == (request_t) get){
        len = mbedtls_snprintf( (char *) buf, sizeof(buf) - 1, GET_REQUEST,
                    opt.request_page );
    }
    else if (req_type == (request_t) post){
        len = mbedtls_snprintf( (char *) buf, sizeof(buf) - 1, POST_REQUEST,
                    opt.request_page );
    }
    
    
    if (headers && n_header > 0)
    {
        for (i = 0; i < n_header; i++)
        {
            len += mbedtls_snprintf( (char*)buf + len, sizeof(buf) -1 - len, "%s\r\n", headers[i]);
        }
    }
    if(body != "\0"){
        len += mbedtls_snprintf( (char*)buf + len, sizeof(buf) -1 - len, "\r\n%s\r\n", body);
    }

    tail_len = (int) strlen( GET_REQUEST_END );

    /* Add padding to GET request to reach opt.request_size in length */
    if( opt.request_size != DFL_REQUEST_SIZE &&
        len + tail_len < opt.request_size )
    {
        memset( buf + len, 'A', opt.request_size - len - tail_len );
        len += opt.request_size - len - tail_len;
    }

    strncpy( (char *) buf + len, GET_REQUEST_END, sizeof(buf) - len - 1 );
    len += tail_len;

    /* Truncate if request size is smaller than the "natural" size */
    if( opt.request_size != DFL_REQUEST_SIZE &&
        len > opt.request_size )
    {
        len = opt.request_size;

        /* Still end with \r\n unless that's really not possible */
        if( len >= 2 ) buf[len - 2] = '\r';
        if( len >= 1 ) buf[len - 1] = '\n';
    }

    if( opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM )
    {   
        mbedtls_printf("Stream: Request length is %d\n", len);
        for( written = 0, frags = 0; written < len; written += ret, frags++ )
        {
            while( ( ret = mbedtls_ssl_write( &ssl, buf + written, len - written ) )
                           <= 0 )
            {
                if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                    ret != MBEDTLS_ERR_SSL_WANT_WRITE )
                {
                    mbedtls_printf( "  mbedtls_ssl_write returned -%#x", -ret );
                    goto exit;
                }
            }
        }
    }
    else /* Not stream, so datagram */
    {   
        mbedtls_printf("Datagram: Request length is %d\n", len);
        do ret = mbedtls_ssl_write( &ssl, buf, len );
        while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE );

        if( ret < 0 )
        {
            mbedtls_printf( "  mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }

        frags = 1;
        written = ret;
    }
    buf[written] = '\0';
    mbedtls_printf("%d bytes written in %d fragments\n", written, frags);
    mbedtls_printf("%s", (char*) buf);
    mbedtls_printf("\n");

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_print_buf(&ssl, 0, __FILE__, __LINE__, "bytes written: ", buf, written);
#endif
    /*
     * 7. Read the HTTP response
     */

    /*
     * TLS and DTLS need different reading styles (stream vs datagram)
     */
    if( opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM )
    {
        do
        {
            len = length - 1;
            memset( output, 0, length);
            ret = mbedtls_ssl_read( &ssl, output, len );

            if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE )
                continue;

            if( ret <= 0 )
            {
                switch( ret )
                {
                    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                        mbedtls_printf( " connection was closed gracefully\n" );
                        ret = 0;
                        goto close_notify;

                    case 0:
                    case MBEDTLS_ERR_NET_CONN_RESET:
                        mbedtls_printf( " connection was reset by peer\n" );
                        ret = 0;
                        goto reconnect;

                    default:
                        mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                        goto exit;
                }
            }

            len = ret;
            mbedtls_printf("Output is %s\n", output);
            mbedtls_printf( "get %d bytes ending with %x\n", len, output[len-1]);
#if defined(MBEDTLS_DEBUG_C)
          mbedtls_debug_print_buf(&ssl, 0, __FILE__, __LINE__, "response", output, len);
#endif
            // TODO: Add full-fledge HTTP parser here
            // possibly from libcurl
            if( ret > 0 && (output[len-1] == '\n' || output[len-1] == '}'))
            {
                ret = 0;
                output[len] = 0;
                break;
            }
            

            output += len;
            length -= len;
        }
#pragma warning (disable: 4127)
        while( 1 );
#pragma warning (default: 4127)
    }
    else /* Not stream, so datagram */
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );

        do ret = mbedtls_ssl_read( &ssl, buf, len );
        while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE );

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_TIMEOUT:
                    mbedtls_printf( " timeout\n" );
                    if( retry_left-- > 0 )
                        goto send_request;
                    goto exit;

                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf( " connection was closed gracefully\n" );
                    ret = 0;
                    goto close_notify;

                default:
                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                    goto exit;
            }
        }

        len = ret;
        buf[len] = '\0';
        mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );
        ret = 0;
    }

    /*
     * 7b. Simulate hard reset and reconnect from same port?
     */
    if( opt.reconnect_hard != 0 )
    {
        opt.reconnect_hard = 0;

        mbedtls_printf( "  . Restarting connection from same port..." );

        if( ( ret = mbedtls_ssl_session_reset( &ssl ) ) != 0 )
        {
            mbedtls_printf( "  mbedtls_ssl_session_reset returned -%#x", -ret );
            goto exit;
        }

        while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( "  mbedtls_ssl_handshake returned -%#x", -ret );
                goto exit;
            }
        }

        mbedtls_printf( " ok\n" );

        goto send_request;
    }

    /*
     * 7c. Continue doing data exchanges?
     */
    if( --opt.exchanges > 0 )
        goto send_request;

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:

    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;

    mbedtls_printf( "closed %s:%s\n", opt.server_addr, opt.server_port );

    /*
     * 9. Reconnect?
     */
reconnect:
    if( opt.reconnect != 0 )
    {
        --opt.reconnect;

        mbedtls_net_free( &server_fd );

#if defined(MBEDTLS_TIMING_C)
        if( opt.reco_delay > 0 )
            mbedtls_net_usleep( 1000000 * opt.reco_delay );
#endif

        mbedtls_printf( "  . Reconnecting with saved session..." );

        if( ( ret = mbedtls_ssl_session_reset( &ssl ) ) != 0 )
        {
            mbedtls_printf( "  mbedtls_ssl_session_reset returned -%#x", -ret );
            goto exit;
        }

        if( ( ret = mbedtls_ssl_set_session( &ssl, &saved_session ) ) != 0 )
        {
            mbedtls_printf( "  mbedtls_ssl_conf_session returned %d\n\n", ret );
            goto exit;
        }

        if( ( ret = mbedtls_net_connect( &server_fd, opt.server_addr, opt.server_port,
                                 opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ?
                                 MBEDTLS_NET_PROTO_TCP : MBEDTLS_NET_PROTO_UDP ) ) != 0 )
        {
            mbedtls_printf( "  mbedtls_net_connect returned -%#x", -ret );
            goto exit;
        }

        if( opt.nbio > 0 )
            ret = mbedtls_net_set_nonblock( &server_fd );
        else
            ret = mbedtls_net_set_block( &server_fd );
        if( ret != 0 )
        {
            mbedtls_printf( "  net_set_(non)block() returned -%#x",
                    -ret );
            goto exit;
        }

        while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( "  mbedtls_ssl_handshake returned -%#x", -ret );
                goto exit;
            }
        }

        mbedtls_printf( " ok\n" );

        goto send_request;
    }

    /*
     * Cleanup and exit
     */
exit:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        LL_CRITICAL("Last error was: -0x%X - %s\n\n", -ret, error_buf );
    }
#endif

    mbedtls_net_free( &server_fd );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_free( &clicert );
    mbedtls_x509_crt_free( &cacert );
    mbedtls_pk_free( &pkey );
#endif
    mbedtls_ssl_session_free( &saved_session );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    // Shell can not handle large exit numbers -> 1 for errors

    return( ret );

usage:
    if( ret == 0 )
        ret = 1;

    mbedtls_printf( USAGE );

    list = mbedtls_ssl_list_ciphersuites();
    while( *list )
    {
        mbedtls_printf(" %-42s", mbedtls_ssl_get_ciphersuite_name( *list ) );
        list++;
        if( !*list )
            break;
        mbedtls_printf(" %s\n", mbedtls_ssl_get_ciphersuite_name( *list ) );
        list++;
    }
    mbedtls_printf("\n");
    goto exit;
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&
          MBEDTLS_CTR_DRBG_C MBEDTLS_TIMING_C */


// Parse the HTML response and return the response body
// Inputs: buf - Raw HTML response
//         slen - Size of buf
// Outputs: ret_body - Message body, stripped of the \r and \n characters at the beginning and the end
//          body_len - Length of the message body
int parse_response(char buf[], char **ret_body, size_t slen, int *body_len){
    mbedtls_printf("Printing the buf inside\n");
    mbedtls_printf("%s", buf);
    int minor_version;
    int stat;
    const char *msg;
    size_t msg_len;
    struct phr_header parsed_headers[4];
    size_t num_headers;
    char content_length[1024];
    static char *inputbuf; /* point to the end of the buffer */
    unsigned char c;
    char *body_start;
    char *body_end;
    mbedtls_printf("Buf length is %d\n", sizeof(buf));                                                                        
    num_headers = sizeof(parsed_headers) / sizeof(parsed_headers[0]);     

    // Test response
    // char *buff = "HTTP/1.1 200 OK\r\nDate: Fri, 31 Dec 1999 23:59:59 GMT\r\nContent-Type: text/plain\r\nContent-Length: 42\r\n\r\nabcdefghijklmnopqrstuvwxyz1234567890abcdef\r\n";

    // Parse the response status, message, and headers                                                                         
    phr_parse_response(buf, slen, &minor_version, &stat, &msg, &msg_len, parsed_headers, &num_headers, 0);                                                                                          
   mbedtls_printf("Printing the buf");
    mbedtls_printf("%s", buf);
    mbedtls_printf("Buf length is %d\n", slen);
    mbedtls_printf("msg is %.*s\n", (int)msg_len, msg);
    mbedtls_printf("status is %d\n", stat);
    mbedtls_printf("headers are:\n");
    char header[1024];
    char body[1024];
    int i;
    for (i = 0; i != num_headers; ++i) {
        mbedtls_printf("%.*s: %.*s\n", (int)parsed_headers[i].name_len, parsed_headers[i].name,
            (int)parsed_headers[i].value_len, parsed_headers[i].value);
        strncpy(header, parsed_headers[i].name, parsed_headers[i].name_len);
        
        // Find and record the content length
        if(strcmp(header, "Content-Length") == 0){
            strncpy(content_length, parsed_headers[i].value, parsed_headers[i].value_len);
        }
        memset(header, 0, strlen(header));
    }

    // Find and record the body, cleaned from the excape characters \r and \n
    body_start = parsed_headers[num_headers-1].value + parsed_headers[num_headers-1].value_len;
    
    while(*body_start == '\r' || *body_start == '\n'){
        mbedtls_printf("Escape char found at the beginning of the response body %c", *body_start);
        ++body_start;
    }
        
    strncpy(body, body_start, strlen(body));
    mbedtls_printf("Body length is %d\n", strlen(body));

    body_end = body + strlen(body)-1;
    while(*body_end == '\r' || *body_end == '\n'){
        mbedtls_printf("Escape char found at the end of the response body %c", body[strlen(body)-1]);
        *body_end = '\0';
        --body_end;
    }

    
    *body_len = strlen(body);
    *ret_body = strdup(body);
    
}

void substitution(char *str, char c1, char c2)
{
  int i;
  for (i=0; (str[i])!='\0'; ++i)
    if (c1 == (str[i]))
      (str[i]) = c2;
}

size_t b64_encoded_size(size_t inlen)
{
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encode(const unsigned char *in, size_t len)
{
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return NULL;

	elen = b64_encoded_size(len);
	out  = malloc(elen+1);
	out[elen] = '\0';

	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	return out;
}

/* A utility function to reverse a string  */
void reverse(char str[], int length)
{
    int start = 0;
    int end = length -1;
    while (start < end)
    {   
        char *temp = *(str+start);
        *(str+start) = *(str+end);
        *(str+end) = temp;
        // swap(*(str+start), *(str+end));
        start++;
        end--;
    }
}
 
// Implementation of itoa()
char* itoa(int num, char* str, int base)
{
    int i = 0;
    int isNegative = 0;
 
    /* Handle 0 explicitly, otherwise empty string is printed for 0 */
    if (num == 0)
    {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }
 
    // In standard itoa(), negative numbers are handled only with
    // base 10. Otherwise numbers are considered unsigned.
    if (num < 0 && base == 10)
    {
        isNegative = 1;
        num = -num;
    }
 
    // Process individual digits
    while (num != 0)
    {
        int rem = num % base;
        str[i++] = (rem > 9)? (rem-10) + 'a' : rem + '0';
        num = num/base;
    }
 
    // If number is negative, append '-'
    if (isNegative)
        str[i++] = '-';
 
    str[i] = '\0'; // Append string terminator
 
    // Reverse the string
    reverse(str, i);
 
    return str;
}

int process_msg3(sgx_ra_msg1_t *msg1, sgx_ra_msg3_t **msg3, size_t msg3_size, attestation_status_t *attestation_status, sgx_platform_info_t *platform_info)
{
    uint32_t quote_sz;
    sgx_mac_t vrfymac;
    char *b64quote;
    sgx_quote_t *q;

    /*
	 * The quote size will be the total msg3 size - sizeof(sgx_ra_msg3_t)
	 * since msg3.quote is a flexible array member.
	 *
	 * Total message size is msg3_size/2 since the income message is in base16.
	 */
	quote_sz = (uint32_t)((msg3_size / 2) - sizeof(sgx_ra_msg3_t));
	
	mbedtls_printf("+++ quote_sz= %lu bytes\n", quote_sz);
    mbedtls_printf("+++ Msg3 inside the verifier enclave is: %s\n", hexstring(*msg3, msg3_size/2));

    mbedtls_printf("msg3.quote = %s\n",
			hexstring((*msg3)->quote, quote_sz));

    /* Make sure Ga matches msg1 */


		mbedtls_printf("+++ Verifying msg3.g_a matches msg1.g_a\n");
		mbedtls_printf("msg1.g_a.gx = %s\n",
			hexstring(msg1->g_a.gx, sizeof(msg1->g_a.gx)));
		mbedtls_printf("msg1.g_a.gy = %s\n",
			hexstring(msg1->g_a.gy, sizeof(msg1->g_a.gy)));
		mbedtls_printf("msg3.g_a.gx = %s\n",
			hexstring((*msg3)->g_a.gx, sizeof((*msg3)->g_a.gx)));
		mbedtls_printf("msg3.g_a.gy = %s\n",
			hexstring((*msg3)->g_a.gy, sizeof((*msg3)->g_a.gy)));
	
	if (memcmp(&(*msg3)->g_a, &msg1->g_a, sizeof(sgx_ec256_public_t)) != 0) {
		mbedtls_printf("msg1.g_a and mgs3.g_a keys don't match\n");
		free(msg3);
		return 0;
	}
	
    /* Validate the MAC of M */


    sgx_rijndael128_cmac_msg(smk, (unsigned char *) &(*msg3)->g_a, sizeof(sgx_ra_msg3_t)-sizeof(sgx_mac_t)+quote_sz, (unsigned char *) vrfymac);
                                                    
		mbedtls_printf("+++ Validating MACsmk(M)\n");
		mbedtls_printf("msg3.mac   = %s\n", hexstring(&(*msg3)->mac, sizeof(sgx_mac_t)));
		mbedtls_printf("calculated = %s\n", hexstring(&vrfymac, sizeof(sgx_cmac_128bit_tag_t)));
	
	if (memcmp(&(*msg3)->mac, &vrfymac, sizeof(sgx_mac_t)) != 0) {
		mbedtls_printf("Failed to verify msg3 MAC\n");
		free(msg3);
		return 0;
	}

    /* Encode the report body as base64 */

	b64quote= b64_encode((char *) &(*msg3)->quote, quote_sz);
	if ( b64quote == NULL ) {
		mbedtls_printf("Could not base64 encode the quote\n");
		free(msg3);
		return 0;
	}
	q= (sgx_quote_t *) (*msg3)->quote;

	
		mbedtls_printf("Msg3 Details (in Verifier)\n");
		mbedtls_printf("msg3.mac                 = %s\n",
			hexstring(&(*msg3)->mac, sizeof((*msg3)->mac)));
		mbedtls_printf("msg3.g_a.gx              = %s\n",
			hexstring((*msg3)->g_a.gx, sizeof((*msg3)->g_a.gx)));
		mbedtls_printf("msg3.g_a.gy              = %s\n",
			hexstring(&(*msg3)->g_a.gy, sizeof((*msg3)->g_a.gy)));
		mbedtls_printf("msg3.ps_sec_prop         = %s\n",
			hexstring(&(*msg3)->ps_sec_prop, sizeof((*msg3)->ps_sec_prop)));
		mbedtls_printf("msg3.quote.version       = %s\n",
			hexstring(&q->version, sizeof(uint16_t)));
		mbedtls_printf("msg3.quote.sign_type     = %s\n",
			hexstring(&q->sign_type, sizeof(uint16_t)));
		mbedtls_printf("msg3.quote.epid_group_id = %s\n",
			hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
		mbedtls_printf("msg3.quote.qe_svn        = %s\n",
			hexstring(&q->qe_svn, sizeof(sgx_isv_svn_t)));
		mbedtls_printf("msg3.quote.pce_svn       = %s\n",
			hexstring(&q->pce_svn, sizeof(sgx_isv_svn_t)));
		mbedtls_printf("msg3.quote.xeid          = %s\n",
			hexstring(&q->xeid, sizeof(uint32_t)));
		mbedtls_printf("msg3.quote.basename      = %s\n",
			hexstring(&q->basename, sizeof(sgx_basename_t)));
		mbedtls_printf("msg3.quote.report_body   = %s\n",
			hexstring(&q->report_body, sizeof(sgx_report_body_t)));
		mbedtls_printf("msg3.quote.signature_len = %s\n",
			hexstring(&q->signature_len, sizeof(uint32_t)));
		mbedtls_printf("msg3.quote.signature     = %s\n",
			hexstring(&q->signature, q->signature_len));

		mbedtls_printf("Enclave Quote (base64) ==> Send to IAS\n");

		mbedtls_printf(b64quote);

		mbedtls_printf("\n");

        /* Verify that the EPID group ID in the quote matches the one from msg1 */

        mbedtls_printf("+++ Validating quote's epid_group_id against msg1\n");
        mbedtls_printf("msg1.egid = %s\n", 
            hexstring(msg1->gid, sizeof(sgx_epid_group_id_t)));
        mbedtls_printf("msg3.quote.epid_group_id = %s\n",
            hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
        

        if ( memcmp(msg1->gid, &q->epid_group_id, sizeof(sgx_epid_group_id_t)) != 0) {
            mbedtls_printf("EPID GID mismatch. Attestation failed.\n");
            free(b64quote);
            free(msg3);
            return 0;
        }

    
        /* Get attestation report from Intel IAS server */
        client_opt_t opt;
        char buf[2024];
        char *body = (char*)malloc((strlen(b64quote) + strlen("{\"isvEnclaveQuote\":\"\"}"))*sizeof(char));
        client_opt_init(&opt);
        opt.debug_level = 1;
        opt.server_addr = "api.trustedservices.intel.com";
        opt.request_page = "/sgx/dev/attestation/v4/report HTTP/1.1";
        char* http_headers[4]; 
        http_headers[0] = "Host: api.trustedservices.intel.com";
        http_headers[1] = "Ocp-Apim-Subscription-Key: a86c71cb05af4c33a7bf9ec34e8ccd64";
        http_headers[2] = "Content-Type: application/json";
        http_headers[3] = (char*)malloc(20);
        char content_length[5];

        // Create the body
        strcpy(body, "{\"isvEnclaveQuote\":\"");
        strncat(body, b64quote, strlen(b64quote));
        strncat(body, "\"}", 2);
       
        

        // Create the content length header
        itoa(strlen(body), content_length, 10);
        strcpy(http_headers[3], "Content-length: ");
        strncat(http_headers[3], content_length, strlen(content_length));

        // Make HTTP request to IAS from inside the enclave
        ssl_client(opt, (request_t) post, http_headers, 4, body, buf, sizeof buf);

        // Parse the response to learn the SigRL
        size_t slen = sizeof(buf) - 1; 
        char *test_body; 
        parse_response(buf, &test_body, slen, strlen(buf));
        // strncpy(*sigrl, test_body, strlen(test_body));
        mbedtls_printf("Attestation report is %s\n", test_body);

}


// The first function called by the verifier
int process_msg01 (uint32_t msg0_extended_epid_group_id, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2, char **sigrl)
{
	mbedtls_printf("\nMsg0 Details (from Verifier)\n");
	mbedtls_printf("msg0.extended_epid_group_id = %u\n",
			msg0_extended_epid_group_id);
	mbedtls_printf("\n");
	
    memset(msg2, 0, sizeof(sgx_ra_msg2_t));
	/* According to the Intel SGX Developer Reference
	 * "Currently, the only valid extended Intel(R) EPID group ID is zero. The
	 * server should verify this value is zero. If the Intel(R) EPID group ID 
	 * is not zero, the server aborts remote attestation"
	 */

	if ( msg0_extended_epid_group_id != 0 ) {
		mbedtls_printf("msg0 Extended Epid Group ID is not zero.  Exiting.\n");
		return 0;
	}

	// Pass msg1 back to the pointer in the caller func
	// memcpy(msg1, &msg01->msg1, sizeof(sgx_ra_msg1_t));
	
	mbedtls_printf("\nMsg1 Details (from Verifier)\n");
	mbedtls_printf("msg1.g_a.gx = %s\n",
		hexstring(&msg1->g_a.gx, sizeof(msg1->g_a.gx)));
	mbedtls_printf("msg1.g_a.gy = %s\n",
		hexstring(&msg1->g_a.gy, sizeof(msg1->g_a.gy)));
	mbedtls_printf("msg1.gid    = %s\n",
		hexstring( &msg1->gid, sizeof(msg1->gid)));
	mbedtls_printf("\n");

	// /* Generate our session key */

    // Generate our session key -- a random EC key using the P-256 curve. This key will become Gb.
    mbedtls_printf("+++ generating session key Gb\n");
    sgx_ecc_state_handle_t p_ecc_handle;
    sgx_ec256_private_t p_private;
    sgx_ec256_public_t p_public;
    sgx_ec256_dh_shared_t p_shared_key;
    sgx_status_t status;
    // unsigned char cmackey[16];
    sgx_cmac_128bit_key_t cmackey;
    sgx_cmac_128bit_tag_t kdk;

	memset(cmackey, 0, SGX_CMAC_KEY_SIZE);

    status = sgx_ecc256_open_context(&p_ecc_handle);
    if(status != SGX_SUCCESS){
        mbedtls_printf("Error in sgx_ecc256_open_context %d\n", status);
        return 1;
    }
    status = sgx_ecc256_create_key_pair(&p_private, &p_public, p_ecc_handle);
    if(status != SGX_SUCCESS){
        mbedtls_printf("Error in sgx_ecc256_create_key_pair %d\n", status);
        return 1;
    }

    // Derive the key derivation key (KDK) from Ga and Gb:
    //     Compute the shared secret using the client's public session key, Ga, and the service provider's private session key (obtained from Step 1), Gb. The result of this operation will be the x coordinate of Gab, denoted as Gabx.
    //     This function returns the shared key in little-endian order, which is the desired outcome.
    mbedtls_printf("+++ generating KDK Gb\n");
    status = sgx_ecc256_compute_shared_dhkey(&p_private, &msg1->g_a, &p_shared_key, p_ecc_handle);
    if(status != SGX_SUCCESS){
        mbedtls_printf("Error in sgx_ecc256_compute_shared_dhkey %d\n", status);
        return 1;
    }
    mbedtls_printf("Shared DH key (Little-endian)   = %s\n",
		hexstring( &p_shared_key, sizeof(p_shared_key)));

    //     Perform an AES-128 CMAC on the little-endian form of Gabx using a block of 0x00 bytes for the key.
    status = sgx_rijndael128_cmac_msg(&cmackey, &p_shared_key, sizeof(p_shared_key), &kdk);
    if(status != SGX_SUCCESS){
        mbedtls_printf("Error in KDK generatrion %d\n", status);
        return 1;
    }
    mbedtls_printf("KDK    = %s\n", hexstring( &kdk, sizeof(kdk)));

    // Derive the SMK from the KDK by performing an AES-128 CMAC on the byte sequence:
    // 0x01 || SMK || 0x00 || 0x80 || 0x00
    sgx_rijndael128_cmac_msg(&kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7, &smk);
    if(status != SGX_SUCCESS){
        mbedtls_printf("Error in SMK generation %d\n", status);
        return 1;
    }
    mbedtls_printf("SMK    = %s\n", hexstring( &smk, sizeof(smk)));

    /*
	 * Build message 2
	 *
	 * A || CMACsmk(A) || SigRL
	 * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
	 *
	 * where:
	 *
	 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga) 
	 *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
	 * Ga     = Client enclave's session key
	 *          (32 bytes)
	 * Gb     = Service Provider's session key
	 *          (32 bytes)
	 * SPID   = The Service Provider ID, issued by Intel to the vendor
	 *          (16 bytes)
	 * TYPE   = Quote type (0= linkable, 1= linkable)
	 *          (2 bytes)
	 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
	 *          (2 bytes)
	 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
	 *          (signed with the Service Provider's private key)
	 *          (64 bytes)
	 *
	 * CMACsmk= AES-128-CMAC(A)
	 *          (16 bytes)
	 * 
	 * || denotes concatenation
	 *
	 * Note that all key components (Ga.x, etc.) are in little endian 
	 * format, meaning the byte streams need to be reversed.
	 *
	 * For SigRL, send:
	 *
	 *  SigRL_size || SigRL_contents
	 *
	 * where sigRL_size is a 32-bit uint (4 bytes). This matches the
	 * structure definition in sgx_ra_msg2_t
	 */

    unsigned char gb_ga[128];

    memcpy(&msg2->spid, datahex(SPID), sizeof(sgx_spid_t));
    msg2->quote_type = (uint16_t) SGX_UNLINKABLE_SIGNATURE;
	msg2->kdf_id = 1;
    memcpy(&msg2->g_b, &p_public, sizeof(p_public));
    // msg2->g_b = p_public;

    /* Get SigRL from Intel IAS server */
    client_opt_t opt;
    char buf[1024];
    client_opt_init(&opt);
    opt.debug_level = 1;
    opt.server_addr = "api.trustedservices.intel.com";
    opt.request_page = "/sgx/dev/attestation/v4/sigrl/00000c1f HTTP/1.1";
    char* http_headers[2]; 
    http_headers[0] = "Host: api.trustedservices.intel.com";
    http_headers[1] = "Ocp-Apim-Subscription-Key: 2f4641eb3f334703adafa46c35556505";

    // Make HTTP request to IAS from inside the enclave
    ssl_client(opt, (request_t) get, http_headers, 2, "\0", buf, sizeof buf);

    // Parse the response to learn the SigRL
    size_t slen = sizeof(buf) - 1; 
    char *test_body; 
    parse_response(buf, &test_body, slen, &msg2->sig_rl_size);
    strncpy(*sigrl, test_body, strlen(test_body));
    mbedtls_printf("SigRL is %s\n", *sigrl);
    mbedtls_printf("SigRL Length is %d\n", msg2->sig_rl_size);
	

    // Calculate the ECDSA signature of:
    // Gbx || Gby || Gax || Gay
    // (traditionally written as r || s) with the service provider's EC private key
    memcpy(gb_ga, msg2->g_b.gx, SGX_ECP256_KEY_SIZE);
    memcpy(&gb_ga[SGX_ECP256_KEY_SIZE], msg2->g_b.gy, SGX_ECP256_KEY_SIZE);
	memcpy(&gb_ga[2*SGX_ECP256_KEY_SIZE], &msg1->g_a.gx, SGX_ECP256_KEY_SIZE);
    memcpy(&gb_ga[3*SGX_ECP256_KEY_SIZE], &msg1->g_a.gy, SGX_ECP256_KEY_SIZE);

	mbedtls_printf("+++ msg2->g_b.gx = %s\n", hexstring(msg2->g_b.gx, SGX_ECP256_KEY_SIZE));
    mbedtls_printf("+++ msg2->g_b.gy = %s\n", hexstring(msg2->g_b.gy, SGX_ECP256_KEY_SIZE));
    mbedtls_printf("+++ &msg1->g_a.gx = %s\n", hexstring(&msg1->g_a.gx, SGX_ECP256_KEY_SIZE));
    mbedtls_printf("+++ &msg1->g_a.gy = %s\n", hexstring(&msg1->g_a.gy, SGX_ECP256_KEY_SIZE));
    mbedtls_printf("+++ gb_ga = %s\n", hexstring(gb_ga, 128));

    sgx_ec256_signature_t signed_gb_ga;
    sgx_ec256_private_t service_private_key;
    memcpy(service_private_key.r, def_service_private_key, SGX_ECP256_KEY_SIZE);
    mbedtls_printf("+++ service private key = %s\n", hexstring(service_private_key.r, sizeof(service_private_key)));
    sgx_ecdsa_sign(&gb_ga, sizeof(gb_ga), &service_private_key, &signed_gb_ga, p_ecc_handle);

    memcpy(msg2->sign_gb_ga.x, signed_gb_ga.x, sizeof(signed_gb_ga.x));
    memcpy(msg2->sign_gb_ga.y, signed_gb_ga.y, sizeof(signed_gb_ga.y));

    mbedtls_printf("+++ r = %s\n", hexstring(signed_gb_ga.x, 32));
    mbedtls_printf("+++ s = %s\n", hexstring(signed_gb_ga.y, 32));

    // Calculate the AES-128 CMAC of:
    // Gb || SPID || Quote_Type || KDF_ID || SigSP
    // using the SMK (derived in Step 3) as the key.

    
    // cmac128(session->smk, (unsigned char *) msg2, 148,
	// 	(unsigned char *) &msg2->mac);

    sgx_rijndael128_cmac_msg(&smk, (unsigned char *)msg2, 148, &msg2->mac);


    mbedtls_printf("Msg2 Details\n");
		mbedtls_printf("msg2->g_b.gx      = %s\n",
			hexstring(&msg2->g_b.gx, sizeof(msg2->g_b.gx)));
		mbedtls_printf("msg2->g_b.gy      = %s\n",
			hexstring(&msg2->g_b.gy, sizeof(msg2->g_b.gy)));
		mbedtls_printf("msg2->spid        = %s\n",
			hexstring(&msg2->spid, sizeof(msg2->spid)));
		mbedtls_printf("msg2->quote_type  = %s\n",
			hexstring(&msg2->quote_type, sizeof(msg2->quote_type)));
		mbedtls_printf("msg2->kdf_id      = %s\n",
			hexstring(&msg2->kdf_id, sizeof(msg2->kdf_id)));
		mbedtls_printf("msg2->sign_gb_ga.x  = %s\n",
			hexstring(&msg2->sign_gb_ga.x, sizeof(msg2->sign_gb_ga.x)));
        mbedtls_printf("msg2->sign_gb_ga.y  = %s\n",
			hexstring(&msg2->sign_gb_ga.y, sizeof(msg2->sign_gb_ga.y)));
		mbedtls_printf("msg2->mac         = %s\n",
			hexstring(&msg2->mac, sizeof(msg2->mac)));
		mbedtls_printf("msg2->sig_rl_size = %s\n",
			hexstring(&msg2->sig_rl_size, sizeof(msg2->sig_rl_size)));
    mbedtls_printf("\n");

    return 1;
	}
