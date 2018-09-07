/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014, Bill Nagel <wnagel@tycoint.com>, Exacq Technologies
 * Copyright (C) 2016-2018, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#if !defined(CURL_DISABLE_SMB) && defined(USE_NTLM) &&  \
  (CURL_SIZEOF_CURL_OFF_T > 4)

#if !defined(USE_WINDOWS_SSPI) || defined(USE_WIN32_CRYPTO)

#define BUILDING_CURL_SMB_C

#ifdef HAVE_PROCESS_H
#include <process.h>
#ifdef CURL_WINDOWS_APP
#define getpid GetCurrentProcessId
#elif !defined(MSDOS)
#define getpid _getpid
#endif
#endif

#ifdef USE_OPENSSL
#  ifndef OPENSSL_NO_MD4
#    include <openssl/md4.h>
#  endif
#  include <openssl/rc4.h>
#ifndef OPENSSL_NO_CMAC
#    include <openssl/cmac.h>
#  endif
#elif defined(USE_GNUTLS_NETTLE)
#  include <nettle/md4.h>
#elif defined(USE_GNUTLS)
#  include <gcrypt.h>
#  define MD4_DIGEST_LENGTH 16
#elif defined(USE_NSS)
#  include <nss.h>
#  include <pk11pub.h>
#  include <hasht.h>
#  include "curl_md4.h"
#elif defined(USE_DARWINSSL)
#  include <CommonCrypto/CommonCryptor.h>
#  include <CommonCrypto/CommonDigest.h>
#elif defined(USE_OS400CRYPTO)
#  include "cipher.mih"  /* mih/cipher */
#  include "curl_md4.h"
#elif defined(USE_WIN32_CRYPTO)
#  include <wincrypt.h>
#endif

#include <stdint.h>
#include <inttypes.h>
#include "smb.h"
#include "urldata.h"
#include "non-ascii.h"
#include "sendf.h"
#include "multiif.h"
#include "connect.h"
#include "progress.h"
#include "transfer.h"
#include "vtls/vtls.h"
#include "curl_ntlm_core.h"
#include "escape.h"
#include "curl_endian.h"
#include "curl_md5.h"
#include "vauth/vauth.h"
#include "curl_base64.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/* Local API functions */
static CURLcode smb_setup_connection(struct connectdata *conn);
static CURLcode smb_connect(struct connectdata *conn, bool *done);
static CURLcode smb_connection_state(struct connectdata *conn, bool *done);
static CURLcode smb_do(struct connectdata *conn, bool *done);
static CURLcode smb_request_state(struct connectdata *conn, bool *done);
static CURLcode smb_done(struct connectdata *conn, CURLcode status,
                         bool premature);
static CURLcode smb_disconnect(struct connectdata *conn, bool dead);
static int smb_getsock(struct connectdata *conn, curl_socket_t *socks,
                       int numsocks);
static CURLcode smb_parse_url_path(struct connectdata *conn);
static CURLcode smb_parse_custom_request(struct connectdata *conn);

/*
 * SMB handler interface
 */
const struct Curl_handler Curl_handler_smb = {
  "SMB",                                /* scheme */
  smb_setup_connection,                 /* setup_connection */
  smb_do,                               /* do_it */
  smb_done,                             /* done */
  ZERO_NULL,                            /* do_more */
  smb_connect,                          /* connect_it */
  smb_connection_state,                 /* connecting */
  smb_request_state,                    /* doing */
  smb_getsock,                          /* proto_getsock */
  smb_getsock,                          /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  smb_disconnect,                       /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  PORT_SMB,                             /* defport */
  CURLPROTO_SMB,                        /* protocol */
  PROTOPT_NONE                          /* flags */
};

#ifdef USE_SSL
/*
 * SMBS handler interface
 */
const struct Curl_handler Curl_handler_smbs = {
  "SMBS",                               /* scheme */
  smb_setup_connection,                 /* setup_connection */
  smb_do,                               /* do_it */
  smb_done,                             /* done */
  ZERO_NULL,                            /* do_more */
  smb_connect,                          /* connect_it */
  smb_connection_state,                 /* connecting */
  smb_request_state,                    /* doing */
  smb_getsock,                          /* proto_getsock */
  smb_getsock,                          /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  smb_disconnect,                       /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  PORT_SMBS,                            /* defport */
  CURLPROTO_SMBS,                       /* protocol */
  PROTOPT_SSL                           /* flags */
};
#endif

#define MAX_PAYLOAD_SIZE   0x8000
#define MAX_MESSAGE_SIZE   (MAX_PAYLOAD_SIZE + 0x1000)
#define MAX_NET_BIOS_PAYLOAD_SIZE   0x10000
#define CLIENTNAME         "curl"
#define SERVICENAME        "?????"
#define PRIMARYDOM         "?"
#define EPOCH_DIFF         11644473600ULL
#define MAX_SHORTNAME_SIZE 12
#define MAX_LONGNAME_SIZE  512
#define MAX_PATH_SIZE      32760
#define MAX_BUFFER_LEN_64  20 /* max length of a uint64 is 20 ascii chars */

/* Append a string to an SMB message */
#define MSGCAT(str)                             \
  strcpy(p, (str));                             \
  p += strlen(str);

/* Append a null-terminated string to an SMB message */
#define MSGCATNULL(str)                         \
  strcpy(p, (str));                             \
  p += strlen(str) + 1;

/* Append a string with length specified to an SMB message */
#define MSGCATLEN(str, len) \
  memcpy(p, (str), (len)); \
  p += (len);

#define SMBBUFWRITE(str, len) \
  memcpy(buf + buf_len, str, len); \
  buf_len += len;

/* SMB is mostly little endian */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || \
  defined(__OS400__)
static unsigned short smb_swap16(unsigned short x)
{
  return (unsigned short) ((x << 8) | ((x >> 8) & 0xff));
}

static unsigned int smb_swap32(unsigned int x)
{
  return (x << 24) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) |
    ((x >> 24) & 0xff);
}

static curl_off_t smb_swap64(curl_off_t x)
{
  return ((curl_off_t) smb_swap32((unsigned int) x) << 32) |
    smb_swap32((unsigned int) (x >> 32));
}

#else
#  define smb_swap16(x) (x)
#  define smb_swap32(x) (x)
#  define smb_swap64(x) (x)
#endif

/* SMB request state */
enum smb_req_state {
  SMB_REQUESTING,
  SMB_TREE_CONNECT,
  SMB_CHECKDFS,
  SMB_OPEN,
  SMB_DOWNLOAD,
  SMB_UPLOAD,
  SMB_DELETE,
  SMB_RENAME,
  SMB_MKDIR,
  SMB_DELDIR,
  SMB_MOVE,
  SMB_FILE_SHORTNAME,
  SMB_FILE_ALLINFO,
  SMB_FINDFIRST,
  SMB_FINDNEXT,
  SMB_CLOSE,
  SMB_TREE_DISCONNECT,
  SMB_MORE_FINDFIRST,
  SMB_MORE_FINDNEXT,
  SMB_DONE,
  SMB2_LOGOFF,
  SMB2_DIR_ALLINFO
};

/* SMB request data */
struct smb_request {
  enum smb_req_state state;
  char *path;
  char *custom;
  char *custom_params;
  char resume_file[255];
  unsigned int resume_filelen;
  unsigned short tid; /* Even if we connect to the same tree as another */
  unsigned short fid; /* request, the tid will be different */
  unsigned short sid;
  unsigned short end_of_search;
  CURLcode result;
};

static void conn_state(struct connectdata *conn, enum smb_conn_state newstate)
{
  struct smb_conn *smbc = &conn->proto.smbc;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* For debug purposes */
  static const char * const names[] = {
    "SMB_NOT_CONNECTED",
    "SMB_CONNECTING",
    "SMB_NEGOTIATE",
    "SMB_SETUP",
    "SMB_CONNECTED",
    /* LAST */
  };

  if(smbc->state != newstate)
    infof(conn->data, "SMB conn %p state change from %s to %s\n",
          (void *)smbc, names[smbc->state], names[newstate]);
#endif

  smbc->state = newstate;
}

static void request_state(struct connectdata *conn,
                          enum smb_req_state newstate)
{
  struct smb_request *req = conn->data->req.protop;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* For debug purposes */
  static const char * const names[] = {
    "SMB_REQUESTING",
    "SMB_TREE_CONNECT",
    "SMB_OPEN",
    "SMB_DOWNLOAD",
    "SMB_UPLOAD",
    "SMB_DELETE",
    "SMB_RENAME",
    "SMB_MKDIR",
    "SMB_DELDIR",
    "SMB_CLOSE",
    "SMB_TREE_DISCONNECT",
    "SMB_DONE",
    /* LAST */
  };

  if(req->state != newstate)
    infof(conn->data, "SMB request %p state change from %s to %s\n",
          (void *)req, names[req->state], names[newstate]);
#endif

  req->state = newstate;
}

/* this should setup things in the connection, not in the easy
   handle */
static CURLcode smb_setup_connection(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  struct smb_request *req;

  /* Initialize the request state */
  conn->data->req.protop = req = calloc(1, sizeof(struct smb_request));
  if(!req)
    return CURLE_OUT_OF_MEMORY;

  /* Parse the URL path */
  result = smb_parse_url_path(conn);
  if(result)
    return result;

  /* Parse the custom request */
   result = smb_parse_custom_request(conn);
   if(result)
     return result;

  return CURLE_OK;
}

static CURLcode smb_connect(struct connectdata *conn, bool *done)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  char *slash;

  (void) done;

  /* Check we have a username and password to authenticate with
  if(!conn->bits.user_passwd)
    return CURLE_LOGIN_DENIED;*/

  /* Initialize the connection state */
  smbc->state = SMB_CONNECTING;
  smbc->recv_buf = malloc(MAX_MESSAGE_SIZE);
  if(!smbc->recv_buf)
    return CURLE_OUT_OF_MEMORY;
  smbc->write_buf = malloc(MAX_MESSAGE_SIZE);
  if(!smbc->write_buf)
    return CURLE_OUT_OF_MEMORY;

  /* Multiple requests are allowed with this connection */
  connkeep(conn, "SMB default");

  /* Parse the username, domain, and password */
  slash = strchr(conn->user, '/');
  if(!slash)
    slash = strchr(conn->user, '\\');

  if(slash) {
    smbc->user = slash + 1;
    smbc->domain = strdup(conn->user);
    if(!smbc->domain)
      return CURLE_OUT_OF_MEMORY;
    smbc->domain[slash - conn->user] = 0;
  }
  else {
    smbc->user = conn->user;
    smbc->domain = strdup("?");
    if(!smbc->domain)
      return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

static CURLcode smb_sign(struct connectdata *conn, struct smb_conn *smbc,
                     size_t msg_len)
{
  char *full_msg;
  unsigned char *security_features;
  unsigned char MAC[16];
  unsigned char *MAC_data;
  MD5_context* MD5c;

  /* The SMB message should be in the upload buffer at this point, as we're
   * called directly after the header is formatted and copied into the upload
   * buffer along with the main body of the message.
   * The structure of the SMB message can be found here:
   * https://msdn.microsoft.com/en-us/library/ee441702.aspx */

  /* set full_msg to the beginning of the message (start of header) - this
   * will be +4 bytes into the buffer as the first 4 bytes are not part of
   * the header */
  full_msg = conn->data->state.ulbuf + 4;

  /* set security_features to the SMB Header field 'SecurityFeatures', which
   * is 14 bytes into the header (+4 for the non-header bytes) */
  security_features = (unsigned char *)conn->data->state.ulbuf + 18;

  /* put sequence in first 4 bytes of signature field */
  memset(security_features, 0, 8);
  security_features[0] = (unsigned char)(smbc->sequence & 0xFF);
  security_features[1] = (unsigned char)((smbc->sequence >> 8) & 0xFF);
  security_features[2] = (unsigned char)((smbc->sequence >> 16) & 0xFF);
  security_features[3] = (unsigned char)((smbc->sequence >> 24) & 0xFF);

  /* calculate MAC signature */
  /* concat the MAC key and entire SMB message, -4 as the smb_header contains
   * 4 extra bytes of data which are not a part of the header structure */
  MAC_data = malloc(sizeof(smbc->MAC_key) + msg_len +
                    sizeof(struct smb_header) - 4);
  if(!MAC_data)
    return CURLE_OUT_OF_MEMORY;
  memcpy(MAC_data, smbc->MAC_key, sizeof(smbc->MAC_key));
  memcpy(MAC_data + sizeof(smbc->MAC_key), full_msg, msg_len +
                                               sizeof(struct smb_header) - 4);

  /* get MD5 hash of all that */
  MD5c = Curl_MD5_init(Curl_DIGEST_MD5);
  if(!MD5c) {
    free(MAC_data);
    return CURLE_OUT_OF_MEMORY;
  }
  Curl_MD5_update(MD5c, MAC_data, (unsigned int)
                                  (sizeof(smbc->MAC_key) + msg_len +
                                   sizeof(struct smb_header) - 4));
  Curl_MD5_final(MD5c, MAC);

  /* put first 8 bytes of MD5 hash in security features */
  memcpy(security_features, MAC, 8);

  /* increment sequence */
  smbc->sequence++;
  free(MAC_data);
  return CURLE_OK;
}

static CURLcode smb_check_sign(struct smb_conn *smbc, char *msg,
                               size_t msg_size)
{
  char *fullmsg;
  char *security_features;
  unsigned char recv_signature[8];
  unsigned char MAC[16];
  unsigned char *MAC_data;
  MD5_context* MD5c;
  int i;

  /* check signature here */
  fullmsg = msg + 4;
  security_features = msg + 18;
  memcpy(recv_signature, security_features, 8);
  MAC_data = malloc(sizeof(smbc->MAC_key) + msg_size);
  if(!MAC_data)
    return CURLE_OUT_OF_MEMORY;

  /* get mac key */
  memcpy(MAC_data, smbc->MAC_key, sizeof(smbc->MAC_key));

  /* put sequence number in sig field */
  memset(security_features, 0, 8);
  security_features[0] = (unsigned char)(smbc->sequence & 0xFF);
  security_features[1] = (unsigned char)((smbc->sequence >> 8) & 0xFF);
  security_features[2] = (unsigned char)((smbc->sequence >> 16) & 0xFF);
  security_features[3] = (unsigned char)((smbc->sequence >> 24) & 0xFF);

  /* concat mac key with received SMB message */
  memcpy(MAC_data + sizeof(smbc->MAC_key), fullmsg, msg_size);

  /* MD5 the whole lot */
  MD5c = Curl_MD5_init(Curl_DIGEST_MD5);
  if(!MD5c) {
    free(MAC_data);
    return CURLE_OUT_OF_MEMORY;
  }
  Curl_MD5_update(MD5c, MAC_data, (unsigned int)
                                  (sizeof(smbc->MAC_key) + msg_size));
  Curl_MD5_final(MD5c, MAC);

  /* check first 8 bytes against 8 bytes sig from SMB */
  free(MAC_data);
  for(i = 0; i < 8; i++) {
    if(recv_signature[i] != MAC[i]) {
      return CURLE_RECV_ERROR;
    }
  }

  /* increment sequence */
  smbc->sequence++;
  return CURLE_OK;
}

static bool is_smb_v3(struct smb_conn * smbc)
{
  return (smbc->smb_version == SMB300_DIALECT
          || smbc->smb_version == SMB302_DIALECT);
}

static bool is_smb_v2(struct smb_conn * smbc)
{
  return (smbc->smb_version == SMB202_DIALECT
          || smbc->smb_version == SMB210_DIALECT
          || is_smb_v3(smbc));
}

static void compute_smb2_message_signature(unsigned char *export_session_key,
                                           unsigned char *full_msg,
                                           size_t message_len,
                                           unsigned char *signature)
{
  unsigned int *resultLen = 0;
  unsigned char hmac_result[HMAC_SHA256_LEN];
  memset(hmac_result, 0, HMAC_SHA256_LEN);
  HMAC(EVP_sha256(), export_session_key, EXPORTED_KEY_LEN, full_msg,
       message_len, hmac_result, resultLen);
  /* The message signature is the first 16 bytes of the HMAC_SHA256 */
  memcpy(signature, hmac_result, SIGNATURE_LEN);
}

static void compute_smb3_message_signature(unsigned char *export_session_key,
                                           unsigned char *full_msg,
                                           size_t message_len,
                                           unsigned char *signature)
{
#ifndef OPENSSL_NO_CMAC
  unsigned int *hmac_result_len = 0;
  unsigned char hmac_result[HMAC_SHA256_LEN];
  memset(hmac_result, 0, HMAC_SHA256_LEN);
  /* This is a concatenation of:
   * the integer 1 (the number of iterations the KDF should go through)
   * the null terminated string "SMB2AESCMAC"
   * a null byte separator
   * the null terminated string "SmbSign"
   * the integer 128 (the desired key length)
   */
  unsigned char context[29] = {0x00, 0x00, 0x00, 0x01,
        0x53, 0x4d, 0x42, 0x32, 0x41, 0x45, 0x53, 0x43, 0x4d, 0x41, 0x43, 0x00,
        0x00,
        0x53, 0x6d, 0x62, 0x53, 0x69, 0x67, 0x6e, 0x00,
        0x00, 0x00, 0x00, 0x80};
  HMAC(EVP_sha256(), export_session_key, EXPORTED_KEY_LEN, context, 29,
       hmac_result, hmac_result_len);

  unsigned char signing_key[SIGNATURE_LEN];
  memset(signing_key, 0, SIGNATURE_LEN);
  memcpy(signing_key, hmac_result, SIGNATURE_LEN);

  size_t resultLen = 0;
  unsigned char cmac_result[AES_128_CMAC_LEN];
  memset(cmac_result, 0, AES_128_CMAC_LEN);
  CMAC_CTX *ctx = CMAC_CTX_new();
  CMAC_Init(ctx, signing_key, SIGNATURE_LEN, EVP_aes_128_cbc(), 0);
  CMAC_Update(ctx, full_msg, message_len);
  CMAC_Final(ctx, cmac_result, &resultLen);

  /* The message signature is the first 16 bytes of the HMAC_SHA256 */
  memcpy(signature, cmac_result, SIGNATURE_LEN);
  CMAC_CTX_free(ctx);
#endif
}

static void compute_message_signature(struct smb_conn *smbc,
                                      unsigned char *full_msg,
                                      size_t message_len,
                                      unsigned char *signature)
{
  if(is_smb_v3(smbc)) {
    compute_smb3_message_signature(smbc->exported_session_key, full_msg,
                                   message_len, signature);
  }
  else {
    compute_smb2_message_signature(smbc->exported_session_key, full_msg,
                                   message_len, signature);
  }
}

/* Recursive function which checks each SMBv2 signature in a packet
 * i.e. handles compound messages */
static CURLcode smb2_check_sign(struct smb_conn *smbc, void **msg,
                                size_t nbt_size, size_t offset)
{
  struct smb2_header * h2 = *msg + offset;
  unsigned char expected_signature[SIGNATURE_LEN];
  memcpy(expected_signature, &h2->signature, SIGNATURE_LEN);

  /* Clear the actual signature so we can recompute it */
  memset(&h2->signature, 0, SIGNATURE_LEN);

  /* Check we have a signature to compare to */
  if(memcmp(expected_signature, &h2->signature, SIGNATURE_LEN) == 0)
    return CURLE_OK;

  size_t msg_size;
  if(h2->next_command)
    msg_size = h2->next_command;
  else
    msg_size = nbt_size - offset;

  unsigned char calculated_signature[SIGNATURE_LEN];
  memset(calculated_signature, 0, SIGNATURE_LEN);
  compute_message_signature(smbc, (void *) h2, msg_size, calculated_signature);

  if(memcmp(calculated_signature, expected_signature, SIGNATURE_LEN) == 0) {
    if(h2->next_command) {
      offset += msg_size;
      return smb2_check_sign(smbc, msg, nbt_size, offset);
    }
    return CURLE_OK;
  }
  /* Message signatures differ, reject message and exit */
  return CURLE_RECV_ERROR;
}

static CURLcode smb_recv_message(struct connectdata *conn, void **msg)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  char *buf = smbc->recv_buf;
  ssize_t bytes_read;
  size_t nbt_size;
  size_t msg_size;
  size_t len = MAX_MESSAGE_SIZE - smbc->got;
  if(smbc->max_transact_size > MAX_MESSAGE_SIZE)
    len = smbc->max_transact_size - smbc->got;
  unsigned short action;
  CURLcode result;

  result = Curl_read(conn, FIRSTSOCKET, buf + smbc->got, len, &bytes_read);
  if(result)
    return result;

  if(!bytes_read)
    return CURLE_OK;

  /* Check for keep-alive packet
   * NetBIOS session keep-alive message type is 0x85
   * If reading start of a new packet and 1st byte is 0x85, keep-alive found */
  if(smbc->got == 0 && buf[0] == (char)0x85) {
    if(bytes_read > 4) {
      /* If buffer has data after the keep-alive packet (more then 4 bytes),
       * then move data back to discard the keep-alive */
      memmove(buf, buf + 4, (size_t)bytes_read - 4);
      bytes_read -= 4;
    }
    else {
      /* else buffer has only a keep-alive, return as if nothing was read */
      return CURLE_OK;
    }
  }

  smbc->got += bytes_read;

  /* Check for a 32-bit nbt header */
  if(smbc->got < sizeof(unsigned int))
    return CURLE_OK;

  nbt_size = Curl_read16_be((const unsigned char *)
                            (buf + sizeof(unsigned short))) +
    sizeof(unsigned int);
  if(smbc->got < nbt_size)
    return CURLE_OK;

  msg_size = sizeof(struct smb_header);
  if(nbt_size >= msg_size + 1) {
    /* Add the word count */
    msg_size += 1 + ((unsigned char) buf[msg_size]) * sizeof(unsigned short);
    if(nbt_size >= msg_size + sizeof(unsigned short)) {
      /* Add the byte count */
      msg_size += sizeof(unsigned short) +
        Curl_read16_le((const unsigned char *)&buf[msg_size]);
      if(nbt_size < msg_size)
        return CURLE_READ_ERROR;
    }
  }

  *msg = buf;

  if(is_smb_v2(smbc)) {
    struct smb2_header *h2 = *msg + sizeof(struct net_bios_header);
    if(!h2->status && smbc->sig_required) {
      size_t offset = sizeof(struct net_bios_header);
      return smb2_check_sign(smbc, msg, nbt_size, offset);
    }
  }
  else {
    struct smb_header *h;
    h = *msg;
    /* Check message signing, if required and response returns success */
    if(smbc->sig_required && !h->status) {
      /* Before checking session setup (command 0x73), look for GUEST flag,
       * as signing is not activated if authenticating as anon or guest */
      if(h->command == 0x73) {
        action = Curl_read16_le((unsigned char *)
                                    (buf + sizeof(struct smb_header) + 5));
        if(action == 0x0001) {
          smbc->sig_required = false;
          return CURLE_OK;
        }
      }
      return smb_check_sign(smbc, *msg, msg_size - 4);
    }
  }
  return CURLE_OK;
}

static void smb_pop_message(struct connectdata *conn)
{
  struct smb_conn *smbc = &conn->proto.smbc;

  smbc->got = 0;
}

static void smb_format_message(struct connectdata *conn, struct smb_header *h,
                               unsigned char cmd, size_t len)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  struct smb_request *req = conn->data->req.protop;
  unsigned int pid;

  memset(h, 0, sizeof(*h));
  h->nbt_length = htons((unsigned short) (sizeof(*h) - sizeof(unsigned int) +
                                          len));
  memcpy((char *)h->magic, "\xffSMB", 4);
  h->command = cmd;
  h->flags = SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES;
  h->flags2 = smb_swap16(SMB_FLAGS2_IS_LONG_NAME
                         | SMB_FLAGS2_KNOWS_LONG_NAME
                         | SMB_FLAGS2_UNICODE_STRINGS
                         | SMB_FLAGS2_NT_ERROR_CODES);
  h->uid = smb_swap16(smbc->uid);
  h->tid = smb_swap16(req->tid);
  pid = getpid();
  h->pid_high = smb_swap16((unsigned short)(pid >> 16));
  h->pid = smb_swap16((unsigned short) pid);
}

static unsigned short calc_credit_charge(unsigned short cmd)
{
  /* CreditCharge =
   (max(SendPayloadSize, Expected ResponsePayloadSize) – 1) / 65536 + 1 */
  /* This breaks READ because we don't accumulate 256 credits by the time
     this is called - if we don't track credits we should just use 1
  if(cmd == SMB2_COM_READ || cmd == SMB2_COM_WRITE)
      return 256;
*/
  return 1;
}

static void smb2_netbios_header(struct net_bios_header *h, size_t len)
{
  memset(h, 0, sizeof(*h));
  h->nbt_length = htons((unsigned short) len);
}

static uint32_t smb2_format_message(struct connectdata *conn,
                                struct smb2_header *h, unsigned short cmd,
                                size_t len, unsigned short credit_rx,
                                size_t offset, enum compound_state compound)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  memset(h, 0, sizeof(*h));
  memcpy((char *)h->protocol_id, "\xfeSMB", 4);
  h->structure_size = 64;
  if(smbc->multi_credit)
    h->credit_charge = calc_credit_charge(cmd);
  h->command = cmd;
  if(smbc->sig_required && cmd > SMB2_COM_LOGOFF)
    h->flags |= SMB2_FLAGS_SIGNED;
  h->credit_rx = htons(credit_rx);
  h->message_id = smb_swap64(++smbc->message_id);
  if(smbc->session_id)
    h->session_id = smbc->session_id;
  if(smbc->tree_id)
    h->tree_id = smbc->tree_id;

  uint32_t next_command = sizeof(struct smb2_header) + len;
  if(compound == FIRST_COMPOUND || compound == SUBSEQUENT_COMPOUND) {
    size_t byte_align = 8 - (next_command % 8);
    if(byte_align < 8) {
      memset(conn->data->state.ulbuf + offset + next_command, 0,
             byte_align);
      next_command += byte_align;
    }
    h->next_command = smb_swap32(next_command);
  }
  if(compound == SUBSEQUENT_COMPOUND || compound == LAST_COMPOUND) {
    h->flags |= SMB2_FLAGS_RELATED_OPERATIONS;
  }
  return next_command;
}

static CURLcode smb_send(struct connectdata *conn, ssize_t len,
                         size_t upload_size)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  ssize_t bytes_written;
  CURLcode result;

  result = Curl_write(conn, FIRSTSOCKET, conn->data->state.ulbuf,
                      len, &bytes_written);
  if(result) {
    return result;
  }

  if(bytes_written != len) {
    smbc->send_size = len;
    smbc->sent = bytes_written;
  }

  smbc->upload_size = upload_size;

  return CURLE_OK;
}

static CURLcode smb_flush(struct connectdata *conn)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  ssize_t bytes_written;
  ssize_t len = smbc->send_size - smbc->sent;
  CURLcode result;

  if(!smbc->send_size)
    return CURLE_OK;

  result = Curl_write(conn, FIRSTSOCKET,
                      conn->data->state.ulbuf + smbc->sent,
                      len, &bytes_written);
  if(result)
    return result;

  if(bytes_written != len) {
    smbc->sent += bytes_written;
  }
  else {
    smbc->send_size = 0;
  }

  return CURLE_OK;
}

static size_t smb_utf16_codepoint_to_utf8(unsigned int utf16,
                                          unsigned char *utf8) {
  int ls, hs;
  int uc = 0;
  if(utf16 < 0x80) {
    utf8[0] = (unsigned char)utf16;
    return 1;
  }
  if(utf16 >= 0x80 && utf16 < 0x800) {
    utf8[0] = (unsigned char)((utf16 >> 6)   | 0xC0);
    utf8[1] = (unsigned char)((utf16 & 0x3F) | 0x80);
    return 2;
  }
  if(utf16 >= 0x800 && utf16 < 0xFFFF) {
    if(utf16 >= 0xD800 && utf16 <= 0xDFFF) {
      /* Ill-formed. */
      return 0;
    }
    utf8[0] = (unsigned char)(((utf16 >> 12)) | 0xE0);
    utf8[1] = (unsigned char)(((utf16 >> 6) & 0x3F) | 0x80);
    utf8[2] = (unsigned char)(((utf16) & 0x3F) | 0x80);
    return 3;
  }
  /* Multi-unit UTF16 code point */
  if(utf16 >= 0x10000 && utf16 < 0xDC000000) {
    /* Split into high and low surrogates */
    ls = 0x3FF & utf16;
    hs = (utf16 >> 16) & 0x3FF;
    uc |= hs << 10;
    uc |= ls;
    uc += 0x10000;
    utf8[0] = (unsigned char)(0xF0 | (uc >> 18));
    utf8[1] = (unsigned char)(0x80 | ((uc >> 12) & 0x3F));
    utf8[2] = (unsigned char)(0x80 | ((uc >> 6) & 0x3F));
    utf8[3] = (unsigned char)(0x80 | ((uc & 0x3F)));
    return 4;
  }
  return 0;
}

static size_t smb_utf16le_to_utf8(const unsigned char *src, size_t srclen,
                                  unsigned char *dest) {
  unsigned char utf8[4];
  size_t dest_len, utf8_len, i;
  unsigned int utf16 = 0;

  /* guard against null source */
  if(src == NULL)
    return 0;
  dest_len = 0;
  for(i = 0; i + 1 < srclen; utf16 = 0) {
    if(src[i + 1] >= 0xD8) {
      if(src[i + 1] >= 0xDC ||
              i + 3 >= srclen || src[i + 3] < 0xDC || src[i + 3] > 0xDF) {
        /* Malformed multi-unit UTF16 character */
        return 0;
      }
      /* Convert to big endian */
      utf16 |= src[i++] << 16;
      utf16 |= src[i++] << 24;
    }
    /* Convert to big endian */
    utf16 |= src[i++];
    utf16 |= src[i++] << 8;

    utf8_len = smb_utf16_codepoint_to_utf8(utf16, utf8);
    if(utf8_len == 0)
      return 0;
    memcpy(dest + dest_len, utf8, utf8_len);
    dest_len += utf8_len;
  }

  return dest_len;
}

static int smb_utf8_codepoint_to_utf16(const unsigned char *input,
                                        const unsigned char **end_ptr)
{
  int i, utf8bytes, mask, uc, hs, ls;
  int rv = 0;

  *end_ptr = input;
  /* NULL check */
  if(input[0] == 0)
    return -1;

  if(input[0] < 0x80) {
    /* If it's less than 128 then it's a single-byte UTF-8 char */
    * end_ptr = input + 1;
    return input[0];
  }

  if(input[0] >= 0xF0 && input[0] < 0xF8) {
    /* If it starts with 11110 then it's a 4-byte UTF-8 char */
    utf8bytes = 4;
  }
  else if(input[0] >= 0xE0 && input[0] < 0xF0) {
    /* If it starts with 1110 then it's a 3-byte UTF-8 char */
    utf8bytes = 3;
  }
  else if((input[0] & 0xC0) == 0xC0) {
    /* If it starts with 110 then it's a 2-byte UTF-8 char */
    utf8bytes = 2;
  }
  else {
    return -3;
  }

  /*
   * Masks
   * (input[0] & 0x07) // 4-byte
   * (input[0] & 0x0F) // 3-byte
   * (input[0] & 0x1F) // 2-byte
   */
  mask = (1 << (7 - utf8bytes)) - 1;
  uc = (input[0] & mask) << ((utf8bytes - 1) * 6);
  for(i = 1; i < utf8bytes; i++) {
    if(input[i] < 0x80 || input[i] > 0xBF) {
      /* The remaining bytes must start 10 so they
       * must be between 128 (10000000) and 191 (10111111) */
      return -2;
    }
    uc |= (input[i] & 0x3F) << (((utf8bytes - i) - 1) * 6);
  }
  if(uc >= 0xD800 && uc < 0xE000) {
    /* Invalid Unicode point */
    return -3;
  }
  * end_ptr = input + utf8bytes;

  if(utf8bytes == 4) {
    /* multi-unit UTF-16 point */
    uc -= 0x10000;
    hs = (0xFFC00 & uc) >> 10;
    hs += 0xD800;
    ls = 0x3FF & uc;
    ls += 0xDC00;

    rv |= hs << 16;
    rv |= ls;
    return rv;
  }
  return uc;
}

static size_t smb_utf8_to_utf16le(const unsigned char *src,
                                  unsigned char *dest) {
  const unsigned char *p;
  size_t dest_len;
  unsigned int utf16;

  /* guard against null source */
  if(src == NULL) return 0;
  dest_len = 0;
  p = src;
  while(p[0] != '\0') {
    utf16 = (unsigned int)smb_utf8_codepoint_to_utf16(p, &p);
    /* convert to chars */
    if((utf16 >> 16) > 0) {
      /* multi-unit UTF-16 char */
      dest[dest_len++] = (unsigned char)(utf16 >> 16);
      dest[dest_len++] = (unsigned char)(utf16 >> 24);
    }
    dest[dest_len++] = (unsigned char)utf16;
    dest[dest_len++] = (unsigned char)(utf16 >> 8);
  }
  dest[dest_len++] = '\0';
  dest[dest_len++] = '\0';
  return dest_len;
}

static CURLcode smb_construct_path(char **path, size_t *pathlen,
                                   const char *hostname,
                                   const char *share,
                                   const char *file)
{
  *pathlen = strlen(hostname) + strlen(share) + 4;
  if(strcmp(file, ""))
    *path = malloc(*pathlen + strlen(file) + 1);
  else
    *path = malloc(*pathlen);
  if(!*path)
    return CURLE_OUT_OF_MEMORY;

  snprintf(*path, *pathlen, "\\\\%s\\%s", hostname, share);
  if(strcmp(file, "") != 0) {
    *pathlen += strlen(file) + 1;
    snprintf(*path + strlen(*path), *pathlen - strlen(*path), "\\%s", file);
  }
  return CURLE_OK;
}

static CURLcode smb_send_message(struct connectdata *conn, unsigned char cmd,
                                 const void *msg, size_t msg_len,
                                 void *bytes, size_t bytes_len)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  CURLcode result = Curl_get_upload_buffer(conn->data);
  if(result)
    return result;
  smb_format_message(conn, (struct smb_header *)conn->data->state.ulbuf,
                     cmd, msg_len + bytes_len);
  memcpy(conn->data->state.ulbuf + sizeof(struct smb_header),
         msg, msg_len);
  if(bytes_len > 0) {
    memcpy(conn->data->state.ulbuf + sizeof(struct smb_header)
           +  msg_len, bytes, bytes_len);
    msg_len += bytes_len;
    free(bytes);
  }

  /* Message signing */
  if(smbc->sig_required) {
    result = smb_sign(conn, smbc, msg_len);
    if(result) {
      return result;
    }
  }

  return smb_send(conn, sizeof(struct smb_header) + msg_len, 0);
}

static void smb2_sign(struct connectdata *conn, size_t offset,
                          size_t msg_len)
{
  struct smb_conn * smbc = &conn->proto.smbc;
  struct smb2_header * smb2_header = (struct smb2_header *)
      (conn->data->state.ulbuf + offset);

  unsigned char signature[SIGNATURE_LEN];
  memset(signature, 0, SIGNATURE_LEN);
  compute_message_signature(smbc, (void *) smb2_header, msg_len, signature);
  memcpy(smb2_header->signature, &signature, SIGNATURE_LEN);
}

static CURLcode smb2_compose_message(struct connectdata *conn,
                                     unsigned short cmd, const void *msg,
                                     size_t msg_len, void *bytes,
                                     size_t bytes_len,
                                     unsigned short credit_rx, size_t *offset,
                                     enum compound_state compound)
{
  struct smb_conn *smbc = &conn->proto.smbc;

  CURLcode result = Curl_get_upload_buffer(conn->data);
  if(result)
    return result;

  /* Check that message isn't too large for the packet */
  size_t packetSize = *offset + sizeof(struct smb2_header) + msg_len
                      + bytes_len;
  if(compound == FIRST_COMPOUND || compound == SUBSEQUENT_COMPOUND)
    packetSize += 8;

  if(packetSize > conn->data->set.upload_buffer_size) {
    if(bytes_len > 0)
      free(bytes);
    return CURLE_FILESIZE_EXCEEDED;
  }

  size_t next_command = smb2_format_message(conn,
                      (struct smb2_header *) (conn->data->state.ulbuf
                                              + *offset),
                      cmd, msg_len + bytes_len, credit_rx, *offset, compound);

  memcpy(conn->data->state.ulbuf + *offset + sizeof(struct smb2_header),
         msg, msg_len);
  if(bytes_len > 0) {
    memcpy(conn->data->state.ulbuf + *offset
           + sizeof(struct smb2_header) + msg_len, bytes, bytes_len);
    free(bytes);
  }

  /* Message signing */
  if(smbc->sig_required && cmd > SMB2_COM_LOGOFF)
    smb2_sign(conn, *offset, next_command);

  *offset += next_command;

  return CURLE_OK;
}

static CURLcode smb2_send_message(struct connectdata *conn, size_t msg_len)
{
  struct net_bios_header net_bios_header;
  smb2_netbios_header(&net_bios_header, msg_len);

  memcpy(conn->data->state.ulbuf, &net_bios_header,
         sizeof(struct net_bios_header));

  return smb_send(conn, sizeof(struct net_bios_header) + msg_len, 0);
}

static CURLcode smb_send_negotiate(struct connectdata *conn)
{
  const char *msg = "\x00\x22\x00\x02NT LM 0.12"
                            "\x00\x02SMB 2.002"
                            "\x00\x02SMB 2.???";

  return smb_send_message(conn, SMB_COM_NEGOTIATE, msg, 37, NULL, 0);
}

static void generate_random_key(unsigned char random[], size_t len)
{
  int i;
  for(i = 0; i < len; i++) {
    random[i] = (unsigned char) (rand() % 256);
  }
}

static CURLcode smb2_send_negotiate(struct connectdata *conn)
{
  const short dialects[] = {SMB202_DIALECT, SMB210_DIALECT, SMB300_DIALECT,
                            SMB302_DIALECT
  };

  struct smb2_negotiate_request request;
  size_t request_length = sizeof(request);
  memset(&request, 0, request_length);
  request.structure_size = 36;
  request.dialect_count = sizeof(dialects) / sizeof(dialects[0]);
  request.security_mode = 1;

  size_t guid_len = 16;
  unsigned char guid[guid_len];
  generate_random_key(guid, guid_len);
  memcpy(request.client_guid, &guid, guid_len);

  size_t bytes_len = sizeof(dialects);
  unsigned char *bytes = malloc(bytes_len);
  int i = 0;
  for(; i < request.dialect_count; i++) {
    short dialect = smb_swap16(dialects[i]);
    memcpy(bytes + (i * sizeof(dialect)), &dialect, sizeof(dialect));
  }

  size_t offset = sizeof(struct net_bios_header);
  smb2_compose_message(conn, SMB2_COM_NEGOTIATE, &request, request_length,
                       bytes, bytes_len, 0, &offset, NOT_COMPOUND);
  return smb2_send_message(conn, sizeof(struct smb2_header) + request_length
                                 + bytes_len);
}

static CURLcode smb2_send_session_setup_type1(struct connectdata *conn)
{
  struct smb2_session_setup_request request;
  struct ntlmdata *ntlm = &conn->ntlm;
  char *base64_type1 = NULL;
  size_t len = 0;

  CURLcode result = Curl_auth_create_ntlm_type1_message(NULL, NULL, NULL, NULL,
                                                        NULL, ntlm,
                                                        &base64_type1, &len);
  if(result) {
    if(base64_type1)
      free(base64_type1);
    return result;
  }

  unsigned char *bytes = NULL;
  size_t byte_count = 0;
  Curl_base64_decode(base64_type1, &bytes, &byte_count);

  if(base64_type1)
    free(base64_type1);

  /* change the ntlm type 1 negotiate flags */
  uint64_t flags;
  memcpy(&flags, bytes + 12, 8);
  flags |= NTLMSSP_NEGOTIATE_128;
  flags |= NTLMSSP_NEGOTIATE_SIGN;
  flags &= ~NTLMSSP_NEGOTIATE_OEM;
  flags |= NTLMSSP_NEGOTIATE_UNICODE;
  memcpy(bytes + 12, &flags, 8);

  /* set parameters */
  memset(&request, 0, sizeof(request));
  request.structure_size = 25;
  request.flags = 0;
  request.security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
  request.capabilities = smb_swap32(SMB2_GLOBAL_CAP_DFS);
  request.security_buffer_offset = sizeof(struct smb2_header)
                                   + sizeof(struct smb2_session_setup_request);
  request.security_buffer_length = smb_swap16((unsigned short)byte_count);

  size_t offset = sizeof(struct net_bios_header);
  smb2_compose_message(conn, SMB2_COM_SESSION_SETUP, &request,
                       sizeof(request), bytes, byte_count, 256,
                       &offset, NOT_COMPOUND);
  return smb2_send_message(conn, sizeof(struct smb2_header) + sizeof(request)
                                 + byte_count);
}

static void cryptRndSessionKey(unsigned char *session_base_key,
                                    unsigned char *rnd_session_key,
                                    unsigned char *crypt_rnd_session_key)
{
#ifdef USE_OPENSSL
  RC4_KEY key;
  int key_len = 16;
  RC4_set_key(&key, key_len, session_base_key);
  RC4(&key, 16, rnd_session_key, crypt_rnd_session_key);
#endif
}

static void compute_signing_keys(struct connectdata * conn,
                                 const char *user, const char *password,
                                 struct smb2_session_setup_request * request,
                                 unsigned char **bytes, size_t *byte_count)
{
  struct smb_conn * smbc = &conn->proto.smbc;

  /* Generate a random session key */
  unsigned char random_session_key[RANDOM_SESSION_KEY_LEN];
  generate_random_key(random_session_key, RANDOM_SESSION_KEY_LEN);
  memcpy(smbc->random_session_key, &random_session_key,
         RANDOM_SESSION_KEY_LEN);

  /* Append the encrypted random session key and update field info */
  unsigned char *new_bytes = malloc((*byte_count) + RANDOM_SESSION_KEY_LEN);
  memcpy(new_bytes, *bytes, *byte_count);
  free(*bytes);

  struct ntlmssp * ntlmresp;
  ntlmresp = (void *) new_bytes;
  ntlmresp->skey_len = smb_swap16((uint16_t) RANDOM_SESSION_KEY_LEN);
  ntlmresp->skey_max = smb_swap16((uint16_t) RANDOM_SESSION_KEY_LEN);
  ntlmresp->skey_off = smb_swap32((uint32_t) (*byte_count));
  ntlmresp->neg_flags |= NTLMSSP_NEGOTIATE_KEY_EXCH;

  unsigned char ntowf[21];
  Curl_ntlm_core_mk_nt_hash(conn->data, password, ntowf);

  /* Split domain and username */
  const char *username = strchr(user, '\\');
  const char *domain = 0;
  size_t dom_len = 0;
  if(!username)
    username = strchr(user, '/');
  if(username) {
    domain = user;
    dom_len = strlen(user) - strlen(username);
    username++;
  }
  else
    username = user;

  unsigned char resp_key_nt[RESP_KEY_NT_LEN];
  Curl_ntlm_core_mk_ntlmv2_hash(username, strlen(username), domain, dom_len,
                                ntowf, resp_key_nt);

  /* Create NTLM temp structure */
  size_t templen = (size_t) (ntlmresp->nt_len - NT_PROOF_STR_LEN);
  unsigned char temp[templen];
  memset(temp, 0, templen);
  memcpy(temp, new_bytes + ntlmresp->nt_off + NT_PROOF_STR_LEN, templen);

  /* Extract the NTProofStr from the NTLM message */
  unsigned char nt_proof_str[NT_PROOF_STR_LEN];
  memset(nt_proof_str, 0, NT_PROOF_STR_LEN);
  memcpy(nt_proof_str, new_bytes + ntlmresp->nt_off, NT_PROOF_STR_LEN);

  /* Calculate the SessionBaseKey/ExportedSessionKey - they are the same when
   * using NTLMv2 for signing */
  unsigned char session_base_key[EXPORTED_KEY_LEN];
  memset(session_base_key, 0, EXPORTED_KEY_LEN);
  Curl_hmac_md5(resp_key_nt, RESP_KEY_NT_LEN, nt_proof_str, NT_PROOF_STR_LEN,
                session_base_key);
  memcpy(smbc->exported_session_key, &session_base_key, EXPORTED_KEY_LEN);

  /* Encrypt the random session key for sending on the wire */
  unsigned char enc_rnd_session_key[RANDOM_SESSION_KEY_LEN];
  cryptRndSessionKey(session_base_key, smbc->random_session_key,
                     enc_rnd_session_key);
  memcpy(new_bytes + (*byte_count), enc_rnd_session_key,
         RANDOM_SESSION_KEY_LEN);

  *bytes = new_bytes;
  *byte_count += RANDOM_SESSION_KEY_LEN;
  (*request).security_buffer_length =
          smb_swap16((unsigned short) (*byte_count));
}

static CURLcode smb2_send_session_setup_type3(struct connectdata *conn)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  struct smb2_session_setup_request request;

  struct ntlmdata *ntlm = &conn->ntlm;
  char *base64_type3 = NULL;
  size_t len = 0;

  unsigned char *bytes = NULL;
  size_t byte_count = 0;

  const char *user = conn->user;
  const char *password = conn->passwd;

  if(strlen(user) == 0 && strlen(password) == 0) {
    /* if attempting anonymous logon then set signing not required,
     * and create an ntlm type 3 request with no authentication negotiation */
    smbc->sig_required = false;

    byte_count = sizeof(struct ntlmssp);
    bytes = malloc(byte_count);
    memset(bytes, 0, byte_count);
    struct ntlmssp *type3_request = (void *)bytes;

    memcpy(&type3_request->identifier, NTLMSSP_SIGNATURE, 7);
    type3_request->msg_type = NTLMSSP_MESSAGE_TYPE;
    type3_request->neg_flags |= NTLMSSP_NEGOTIATE_ANONYMOUS;
    type3_request->neg_flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
    type3_request->lm_off = sizeof(struct ntlmssp);
    type3_request->nt_off = sizeof(struct ntlmssp);
    type3_request->dom_off = sizeof(struct ntlmssp);
    type3_request->usr_off = sizeof(struct ntlmssp);
    type3_request->grp_off = sizeof(struct ntlmssp);
    type3_request->skey_off = sizeof(struct ntlmssp);
  }
  else {
    CURLcode result = Curl_auth_create_ntlm_type3_message(conn->data, user,
                                                          password, ntlm,
                                                          &base64_type3, &len);
    if(result) {
      if(base64_type3)
        free(base64_type3);
      return result;
    }

    Curl_base64_decode(base64_type3, &bytes, &byte_count);

    if(base64_type3)
      free(base64_type3);

    /* at the moment the neg flags are copied from type2, so we need to clear
     * flags that we are not sending back */
    struct ntlmssp * type3_request;
    type3_request = (void *) bytes;
    type3_request->neg_flags &= ~NTLMSSP_NEGOTIATE_DOMAIN;
    type3_request->neg_flags &= ~NTLMSSP_NEGOTIATE_TARGET_INFO;
  }

  /* set parameters */
  memset(&request, 0, sizeof(request));
  request.structure_size = 25;
  request.flags = 0;
  request.security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
  request.capabilities = smb_swap32(SMB2_GLOBAL_CAP_DFS);
  request.security_buffer_offset = sizeof(struct smb2_header)
                                   + sizeof(struct smb2_session_setup_request);
  request.security_buffer_length = smb_swap16((unsigned short)byte_count);

  if(smbc->sig_required)
    compute_signing_keys(conn, user, password, &request, &bytes, &byte_count);

  size_t offset = sizeof(struct net_bios_header);
  smb2_compose_message(conn, SMB2_COM_SESSION_SETUP, &request, sizeof(request),
                       bytes, byte_count, 256, &offset, NOT_COMPOUND);
  return smb2_send_message(conn, sizeof(struct smb2_header) + sizeof(request)
                                 + byte_count);
}

static CURLcode smb_send_setup(struct connectdata *conn)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  struct smb_setup msg;
  char *p;
  char *bytes;
  unsigned char utf16[MAX_LONGNAME_SIZE];
  size_t utf16len, byte_count;
  unsigned char lm[24];
  unsigned char nt[24];

  /* ensure bytes to be sent will not exceed maximum size */
  utf16len = smb_utf8_to_utf16le((unsigned char *)smbc->user, utf16);
  byte_count = sizeof(lm) + sizeof(nt);
  byte_count += utf16len + (strlen(smbc->domain)*2);
  byte_count += strlen(OS)*2 + strlen(CLIENTNAME)*2 + (4*2) + 1; /* 4 null */
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_setup))
    return CURLE_FILESIZE_EXCEEDED;
  bytes = malloc(byte_count + 1);
  if(!bytes)
    return CURLE_OUT_OF_MEMORY;
  p = bytes;

  /* get the responses */
  memcpy(lm, smbc->lm_resp, 24);
  memcpy(nt, smbc->nt_resp, 24);

  /* set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_SETUP_ANDX;
  msg.andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg.max_buffer_size = smb_swap16(MAX_MESSAGE_SIZE);
  msg.max_mpx_count = smb_swap16(1);
  msg.vc_number = smb_swap16(1);
  msg.session_key = smb_swap32(smbc->session_key);
  msg.capabilities = smb_swap32(SMB_CAP_LARGE_FILES | SMB_CAP_UNICODE_STRINGS
                                | SMB_CAP_NT_SMBS | SMB_CAP_NT_STATUS);
  msg.lengths[0] = smb_swap16(sizeof(lm));
  msg.lengths[1] = smb_swap16(sizeof(nt));

  /* construct bytes */
  msg.byte_count = smb_swap16((unsigned short)byte_count);
  memset(bytes, 0, byte_count + 1);
  MSGCATLEN(lm, sizeof(lm));
  MSGCATLEN(nt, sizeof(nt));
  p++; /* single padding byte for unicode  */
  MSGCATLEN(utf16, utf16len); /* username */
  utf16len = smb_utf8_to_utf16le((unsigned char *)smbc->domain, utf16);
  MSGCATLEN(utf16, utf16len); /* Domain Name */
  utf16len = smb_utf8_to_utf16le((unsigned char *)OS, utf16);
  MSGCATLEN(utf16, utf16len); /* OS */
  utf16len = smb_utf8_to_utf16le((unsigned char *)CLIENTNAME, utf16);
  MSGCATLEN(utf16, utf16len); /* Clientname */

  return smb_send_message(conn, SMB_COM_SETUP_ANDX, &msg, sizeof(msg),
                          bytes, byte_count);
}

static CURLcode smb_send_tree_connect(struct connectdata *conn)
{
  CURLcode result;
  struct smb_request *req = conn->data->req.protop;
  struct smb_tree_connect msg;
  struct smb_conn *smbc = &conn->proto.smbc;
  char *p;
  char *path;
  char *bytes;
  unsigned char *utf16;
  size_t pathlen, utf16len, byte_count;

  /* create path */
  if(req->custom && !strcasecmp("checkdfs", req->custom))
    result = smb_construct_path(&path, &pathlen, conn->host.name, "IPC$", "");
  else
    result = smb_construct_path(&path, &pathlen, conn->host.name,
                                smbc->share, "");
  if(result)
    return result;

  /* convert path to unicode */
  utf16 = malloc((pathlen + 1)*2);
  if(!utf16) {
    free(path);
    return CURLE_OUT_OF_MEMORY;
  }
  utf16len = smb_utf8_to_utf16le((unsigned char *)path, utf16);
  free(path);

  /* ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16len + strlen(SERVICENAME) + 2; /* 2 nulls */
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header)
                  - sizeof(struct smb_tree_connect))
    return CURLE_FILESIZE_EXCEEDED;
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_TREE_CONNECT_ANDX;
  msg.andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg.pw_len = 1;

  /* construct bytes */
  msg.byte_count = smb_swap16((unsigned short)byte_count);
  memset(bytes, 0, byte_count + 1);
  p++; /* 1 byte of padding */
  MSGCATLEN(utf16, utf16len); /* copy path onto message */
  MSGCATNULL(SERVICENAME); /* Match any type of service */

  free(utf16);
  return smb_send_message(conn, SMB_COM_TREE_CONNECT_ANDX, &msg, sizeof(msg),
                          bytes, byte_count + 1);
}

static CURLcode smb2_send_tree_connect(struct connectdata *conn)
{
  CURLcode result;
  struct smb_conn *smbc = &conn->proto.smbc;
  struct smb_request *req = conn->data->req.protop;
  struct smb2_tree_connect_request msg;
  char *path;
  unsigned char *bytes = NULL;
  size_t pathlen;
  size_t byte_count;

  /* create path */
  if(req->custom && !strcasecmp("checkdfs", req->custom))
    result = smb_construct_path(&path, &pathlen, conn->host.name, "IPC$", "");
  else
    result = smb_construct_path(&path, &pathlen, conn->host.name, smbc->share,
                                "");
  if(result)
    return result;

  /* convert path to unicode */
  bytes = malloc((pathlen)*2);
  if(!bytes) {
    free(path);
    return CURLE_OUT_OF_MEMORY;
  }
  byte_count = smb_utf8_to_utf16le((unsigned char *)path, bytes);
  byte_count -= 2; /* SMBv2 does not include the two null terminators */
  free(path);

  /* set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.structure_size = 9;
  msg.path_offset = smb_swap16(sizeof(struct smb2_header)
                               + sizeof(struct smb2_tree_connect_request));
  msg.path_length = smb_swap16((short)byte_count);

  size_t offset = sizeof(struct net_bios_header);
  result = smb2_compose_message(conn, SMB2_COM_TREE_CONNECT, &msg, sizeof(msg),
                       bytes, byte_count, 1, &offset, NOT_COMPOUND);
  if(result)
    return result;
  return smb2_send_message(conn, sizeof(struct smb2_header)  + sizeof(msg)
                                 + byte_count);
}

static CURLcode smb_send_open(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_nt_create msg;
  size_t byte_count;
  char *p;
  unsigned char *utf16;
  char *bytes;
  size_t utf16len;

  /* convert path to unicode */
  utf16 = malloc((strlen(req->path) + 1) * 2);
  if(!utf16) {
    return CURLE_OUT_OF_MEMORY;
  }
  utf16len = smb_utf8_to_utf16le((unsigned char *) req->path, utf16);

  /* ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16len + 1;
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_nt_create)) {
    free(utf16);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_NT_CREATE_ANDX;
  msg.andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg.share_access = smb_swap32(SMB_FILE_SHARE_ALL);
  if(conn->data->set.upload) {
    msg.access = smb_swap32(SMB_GENERIC_READ | SMB_GENERIC_WRITE);
    msg.create_disposition = smb_swap32(SMB_FILE_OVERWRITE_IF);
  }
  else {
    msg.access = smb_swap32(SMB_GENERIC_READ);
    msg.create_disposition = smb_swap32(SMB_FILE_OPEN);
  }
  msg.name_length = smb_swap16((unsigned short)(byte_count - 1));

  /* construct bytes */
  msg.byte_count = smb_swap16((unsigned short)byte_count);
  memset(bytes, 0, byte_count + 1);
  p++; /* one byte of padding */
  memcpy(p, utf16, utf16len);

  free(utf16);
  return smb_send_message(conn, SMB_COM_NT_CREATE_ANDX, &msg, sizeof(msg),
                          bytes, byte_count + 1);
}

static CURLcode smb_send_close(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_close msg;

  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_CLOSE;
  msg.fid = smb_swap16(req->fid);

  return smb_send_message(conn, SMB_COM_CLOSE, &msg, sizeof(msg), NULL, 0);
}

static CURLcode smb_send_tree_disconnect(struct connectdata *conn)
{
  struct smb_tree_disconnect msg;

  memset(&msg, 0, sizeof(msg));

  return smb_send_message(conn, SMB_COM_TREE_DISCONNECT, &msg, sizeof(msg),
                          NULL, 0);
}

static CURLcode smb2_send_tree_disconnect(struct connectdata *conn)
{
  struct smb2_tree_disconnect_request msg;

  memset(&msg, 0, sizeof(msg));
  msg.structure_size = 4;

  size_t offset = sizeof(struct net_bios_header);
  smb2_compose_message(conn, SMB2_COM_TREE_DISCONNECT, &msg, sizeof(msg),
                       NULL, 0, 1, &offset, NOT_COMPOUND);
  return smb2_send_message(conn, sizeof(struct smb2_header) + sizeof(msg));
}

static CURLcode smb2_send_logoff(struct connectdata *conn)
{
  struct smb2_logoff_request msg;
  memset(&msg, 0, sizeof(msg));
  msg.structure_size = 4;

  size_t offset = sizeof(struct net_bios_header);
  smb2_compose_message(conn, SMB2_COM_LOGOFF, &msg, sizeof(msg), NULL, 0, 1,
                       &offset, NOT_COMPOUND);
  return smb2_send_message(conn, sizeof(struct smb2_header) + sizeof(msg));
}

static CURLcode smb2_compose_create(struct connectdata *conn,
                                enum smb_req_state req_state, void *bytes,
                                size_t bytes_len, size_t *offset,
                                enum compound_state compound)
{
  memset(&(conn->proto.smbc.file_id), 0, 16);

  struct smb2_create_request request;

  memset(&request, 0, sizeof(request));
  request.structure_size = 57;
  request.impersonation_level = SMB2_IMPERSONATION_IMPERSONATE;
  switch(req_state) {
    case SMB_OPEN:
      request.desired_access = SMB2_FILE_READ_DATA | SMB2_FILE_READ_ATTRIBUTES
                               | SMB2_READ_CONTROL;
      request.file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
      request.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE
                             | SMB2_FILE_SHARE_DELETE;
      if(conn->data->set.upload) {
        request.desired_access |= SMB2_FILE_WRITE_DATA | SMB2_FILE_APPEND_DATA;
        request.create_disposition = SMB2_FILE_CREATE;
        request.create_options = SMB2_FILE_SEQUENTIAL_ONLY;
      }
      else {
        request.create_disposition = SMB2_FILE_OPEN;
      }
      break;

    case SMB_DELETE:
      request.desired_access = SMB2_FILE_READ_ATTRIBUTES | SMB2_DELETE
                              | SMB2_SYNCHRONIZE;
      request.file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
      request.create_disposition = SMB2_FILE_OPEN;
      break;

    case SMB_RENAME:
      request.desired_access = SMB2_DELETE;
      request.create_disposition = SMB2_FILE_OPEN;
      break;

    case SMB_MKDIR:
      request.desired_access = SMB2_FILE_READ_ATTRIBUTES;
      request.file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
      request.create_disposition = SMB2_FILE_CREATE;
      request.create_options = SMB2_FILE_DIRECTORY_FILE;
      break;

    case SMB_FINDFIRST:
      request.desired_access = SMB2_FILE_LIST_DIRECTORY
                               | SMB2_FILE_READ_ATTRIBUTES;
      request.file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
      request.create_disposition = SMB2_FILE_OPEN;
      request.create_options = SMB2_FILE_DIRECTORY_FILE;
      request.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE
                             | SMB2_FILE_SHARE_DELETE;
      break;

    case SMB_FILE_ALLINFO:
      request.desired_access = SMB2_FILE_READ_DATA | SMB2_FILE_READ_ATTRIBUTES;
      request.file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
      request.create_disposition = SMB2_FILE_OPEN;
      request.create_options = SMB2_FILE_NON_DIRECTORY_FILE;
      request.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE
                             | SMB2_FILE_SHARE_DELETE;
      break;

    case SMB2_DIR_ALLINFO:
      request.desired_access = SMB2_FILE_READ_DATA | SMB2_FILE_READ_ATTRIBUTES;
      request.file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
      request.create_disposition = SMB2_FILE_OPEN;
      request.create_options = SMB2_FILE_DIRECTORY_FILE;
      request.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE
                             | SMB2_FILE_SHARE_DELETE;
      break;

    default:
      break;
  }

  request.name_offset = smb_swap16(sizeof(struct smb2_header)
                       + sizeof(struct smb2_create_request));
  request.name_length = smb_swap16((unsigned short)bytes_len);

  if(bytes_len == 0) {
    /* The buffer of a create request MUST be at least one byte in length,
    * so if byte_count is zero add an extra byte to the msg_len to send */
    bytes_len = 1;
    if(bytes)
      free(bytes);
    bytes = calloc(1, 1);
  }

  return smb2_compose_message(conn, SMB2_COM_CREATE, &request, sizeof(request),
                       bytes, bytes_len, 1, offset, compound);
}

static CURLcode smb2_compose_set_info(struct connectdata *conn,
                                      enum smb_req_state req_state,
                                      void *bytes, size_t bytes_len,
                                      size_t *offset,
                                      enum compound_state compound)
{
  struct smb2_set_info_request request;
  memset(&request, 0, sizeof(request));

  request.structure_size = 33;
  request.info_type = SMB2_INFO_FILE;
  switch(req_state) {
    case SMB_DELETE:
      request.file_info_class = 0xD; /* FileDispositionInformation */
      break;

    case SMB_RENAME:
      request.file_info_class = 0xA; /* FileRenameInformation */
      break;

    default:
      break;
  }
  request.buffer_length = smb_swap32((uint32_t) bytes_len);
  request.buffer_offset = sizeof(struct smb2_header)
                       + sizeof(struct smb2_set_info_request);
  memset(&request.file_id, 0xFF, 16);

  return smb2_compose_message(conn, SMB2_COM_SET_INFO, &request,
                       sizeof(struct smb2_set_info_request),
                       bytes, bytes_len, 1, offset, compound);
}

static CURLcode smb2_compose_close(struct connectdata *conn,
                               enum smb_req_state req_state, size_t *offset,
                               enum compound_state compound)
{
  struct smb2_close_request request;
  memset(&request, 0, sizeof(request));

  request.structure_size = 24;

  if(req_state == SMB_FILE_ALLINFO)
    request.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;

  memcpy(&request.file_id, &conn->proto.smbc.file_id, 16);

  unsigned char *bytes;
  size_t bytes_len = 1;
  bytes = malloc(bytes_len);
  *bytes = 1;

  return smb2_compose_message(conn, SMB2_COM_CLOSE, &request,
                       sizeof(struct smb2_close_request),
                       bytes, bytes_len, 1, offset, compound);
}

static CURLcode smb2_send_close(struct connectdata *conn)
{
  CURLcode result;
  size_t offset = sizeof(struct net_bios_header);
  result = smb2_compose_close(conn, SMB_CLOSE, &offset, NOT_COMPOUND);
  if(result)
    return result;

  return smb2_send_message(conn, offset - sizeof(struct net_bios_header));
}

static CURLcode smb2_send_delete(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  size_t byte_count;
  unsigned char *bytes;
  CURLcode result;

  /* reject the command if it has no path or there's \ on the end of path */
  if(strlen(req->path) == 0) {
    failf(conn->data, "No path specified");
    return CURLE_URL_MALFORMAT;
  }
  if(strcmp(req->path + strlen(req->path) - 1, "\\") == 0) {
    failf(conn->data, "Path does not point to a file");
    return CURLE_URL_MALFORMAT;
  }

  /* Convert path to utf16_le */
  bytes = malloc((strlen(req->path) + 1)*2);
  if(!bytes) {
    return CURLE_OUT_OF_MEMORY;
  }
  byte_count = smb_utf8_to_utf16le((unsigned char *)req->path, bytes);
  byte_count -= 2; /* SMBv2 does not include the two null terminators */

  size_t compound_offset = sizeof(struct net_bios_header);
  result = smb2_compose_create(conn, SMB_DELETE, bytes, byte_count,
                               &compound_offset, FIRST_COMPOUND);
  if(result)
    return result;

  /* create FileDispositionInformation (DeletePending, 1 byte set to 1) */
  unsigned char *info_bytes;
  size_t info_bytes_len = 1;
  info_bytes = malloc(info_bytes_len);
  *info_bytes = 1;

  result = smb2_compose_set_info(conn, SMB_DELETE, info_bytes, info_bytes_len,
                                 &compound_offset, SUBSEQUENT_COMPOUND);
  if(result)
    return result;

  result = smb2_compose_close(conn, SMB_DELETE, &compound_offset,
                              LAST_COMPOUND);
  if(result)
    return result;

  return smb2_send_message(conn, compound_offset
                           - sizeof(struct net_bios_header));
}

static CURLcode smb2_send_rename_or_move(struct connectdata *conn, char *dest)
{
  CURLcode result;
  struct smb_request *req = conn->data->req.protop;
  unsigned char *bytes_src;
  unsigned char *bytes_dst;
  size_t byte_count_src;
  size_t byte_count_dst;

  /* Convert source path to utf16_le */
  bytes_src = malloc((strlen(req->path) + 1)*2);
  if(!bytes_src) {
    free(dest);
    return CURLE_OUT_OF_MEMORY;
  }
  byte_count_src = smb_utf8_to_utf16le((unsigned char *)req->path, bytes_src);
  byte_count_src -= 2; /* SMBv2 does not include the two null terminators */

  /* Convert destination to utf16_le */
  bytes_dst = malloc((strlen(dest) + 1)*2);
  if(!bytes_dst) {
    free(dest);
    free(bytes_src);
    return CURLE_OUT_OF_MEMORY;
  }
  byte_count_dst = smb_utf8_to_utf16le((unsigned char *)dest, bytes_dst);
  byte_count_dst -= 2; /* SMBv2 does not include the two null terminators */
  free(dest);

  /* create the file rename information */
  size_t info_length = sizeof(struct smb2_file_rename_information);
  size_t byte_count_info = info_length + byte_count_dst;
  void *bytes_info = calloc(byte_count_info, sizeof(char));
  if(!bytes_info) {
    free(bytes_src);
    free(bytes_dst);
    return CURLE_OUT_OF_MEMORY;
  }

  struct smb2_file_rename_information *info = bytes_info;
  info->file_name_length = smb_swap32((uint32_t)byte_count_dst);

  memcpy(bytes_info + info_length, bytes_dst, byte_count_dst); /* file name */
  free(bytes_dst);

  size_t compound_offset = sizeof(struct net_bios_header);
  result = smb2_compose_create(conn, SMB_RENAME, bytes_src, byte_count_src,
                               &compound_offset, FIRST_COMPOUND);
  if(result) {
    free(bytes_info);
    return result;
  }

  result = smb2_compose_set_info(conn, SMB_RENAME, bytes_info, byte_count_info,
                                 &compound_offset, SUBSEQUENT_COMPOUND);
  if(result)
    return result;

  result = smb2_compose_close(conn, SMB_RENAME, &compound_offset,
                              LAST_COMPOUND);
  if(result)
    return result;

  return smb2_send_message(conn, compound_offset
                                 - sizeof(struct net_bios_header));
}

static CURLcode smb2_send_rename(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  char *dest;
  char *p;

  /* reject the command if it has no path or there's \ on the end of path
   * or no custom parameter (destination name) specified */
  if(req->path == NULL || strlen(req->path) == 0) {
    failf(conn->data, "No path specified");
    return CURLE_URL_MALFORMAT;
  }
  if(strcmp(req->path + strlen(req->path) - 1, "\\") == 0) {
    failf(conn->data, "Path does not point to a file");
    return CURLE_URL_MALFORMAT;
  }
  if(req->custom_params == NULL || strlen(req->custom_params) == 0) {
    failf(conn->data, "No destination name specified");
    return CURLE_URL_MALFORMAT;
  }

  /* create destination path */
  dest = calloc(strlen(req->custom_params) + strlen(req->path) + 1,
                sizeof(char));
  if(!dest)
    return CURLE_OUT_OF_MEMORY;

  memcpy(dest, req->path, strlen(req->path) + 1);
  p = strrchr(dest, '\\');
  if(!p)
    strcpy(dest, req->custom_params);
  else
    strcpy(p + 1, req->custom_params);

  return smb2_send_rename_or_move(conn, dest);
}

static CURLcode smb2_send_move(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  char *dest;
  char *p;
  char *slash;

  /* reject the command if it has:
   * no path/custom param
   * \ on the end of path
   * no / on the end of custom param */
  if(req->path == NULL || strlen(req->path) == 0) {
    failf(conn->data, "No path specified");
    return CURLE_URL_MALFORMAT;
  }
  if(req->custom_params == NULL || strlen(req->custom_params) == 0) {
    failf(conn->data, "No destination specified");
    return CURLE_URL_MALFORMAT;
  }
  if(strcmp(req->path + strlen(req->path) - 1, "\\") == 0 ||
     strcmp(req->custom_params + strlen(req->custom_params) - 1, "/") != 0) {
    failf(conn->data, "Invalid path/custom parameter");
    return CURLE_URL_MALFORMAT;
  }

  slash = req->custom_params;
  for(; *slash; slash++) {
    if(*slash == '/')
      *slash = '\\';
  }

  /* create destination path */
  dest = calloc(strlen(req->custom_params) + strlen(req->path) + 1,
              sizeof(char));
  if(!dest)
    return CURLE_OUT_OF_MEMORY;

  memcpy(dest, req->custom_params, strlen(req->custom_params) + 1);
  p = strrchr(req->path, '\\');
  if(p) {
    p++;
    memcpy(dest + strlen(dest), p, strlen(p) + 1);
  }
  else
    memcpy(dest + strlen(dest), req->path, strlen(req->path));

  return smb2_send_rename_or_move(conn, dest);
}

static CURLcode smb2_send_mkdir(struct connectdata *conn)
{
  CURLcode result;
  struct smb_request *req = conn->data->req.protop;
  size_t byte_count;
  unsigned char *bytes;
  char *path;

  /* reject the command if there's no \ on the end of path */
  if(strlen(req->path) != 0) {
    if(strcmp(req->path + strlen(req->path) - 1, "\\") != 0) {
      failf(conn->data, "Path should not point to a file");
      return CURLE_URL_MALFORMAT;
    }
  }

  /* construct path */
  path = calloc(strlen(req->path) + strlen(req->custom_params) + 1,
                sizeof(char));
  if(!path)
    return CURLE_OUT_OF_MEMORY;

  /* ensure full path if not directly on the share */
  if(req->path)
    snprintf(path, strlen(req->path) + strlen(req->custom_params) + 1, "%s%s",
             req->path, req->custom_params);
  else
    strcpy(path, req->custom_params);

  /* Convert path to utf16_le */
  bytes = malloc((strlen(path) + 1) * 2);
  if(!bytes) {
    free(path);
    return CURLE_OUT_OF_MEMORY;
  }
  byte_count = smb_utf8_to_utf16le((unsigned char *)path, bytes);
  byte_count -= 2; /* SMBv2 does not include the two null terminators */
  free(path);

  size_t compound_offset = sizeof(struct net_bios_header);
  result = smb2_compose_create(conn, SMB_MKDIR, bytes, byte_count,
                               &compound_offset, FIRST_COMPOUND);
  if(result)
    return result;

  result = smb2_compose_close(conn, SMB_MKDIR, &compound_offset,
                              LAST_COMPOUND);
  if(result)
    return result;

  return smb2_send_message(conn, compound_offset
                                 - sizeof(struct net_bios_header));
}

static CURLcode smb_send_read(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  curl_off_t offset = conn->data->req.offset;
  struct smb_read msg;

  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_READ_ANDX;
  msg.andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg.fid = smb_swap16(req->fid);
  msg.offset = smb_swap32((unsigned int) offset);
  msg.offset_high = smb_swap32((unsigned int) (offset >> 32));
  msg.min_bytes = smb_swap16(MAX_PAYLOAD_SIZE);
  msg.max_bytes = smb_swap16(MAX_PAYLOAD_SIZE);

  return smb_send_message(conn, SMB_COM_READ_ANDX, &msg, sizeof(msg), NULL, 0);
}

static CURLcode smb_send_write(struct connectdata *conn)
{
  struct smb_write *msg;
  struct smb_request *req = conn->data->req.protop;
  struct smb_conn *smbc = &conn->proto.smbc;
  size_t nread = 0;
  size_t byte_count;
  curl_off_t offset = conn->data->req.offset;
  curl_off_t upload_size = conn->data->req.size - conn->data->req.bytecount;
  CURLcode result = Curl_get_upload_buffer(conn->data);
  if(result)
    return result;
  msg = (struct smb_write *)conn->data->state.ulbuf;
  int msgsize = sizeof(*msg);

  if(upload_size >= MAX_PAYLOAD_SIZE - 1) /* There is one byte of padding */
    upload_size = MAX_PAYLOAD_SIZE - 1;

  /* Ensure we will read no more than upload_buffer_size, taking into account
   * the message that we will be appending to */
  if(smbc->sig_required) {
    if(upload_size >= conn->data->set.upload_buffer_size - msgsize) {
      nread = conn->data->set.upload_buffer_size - msgsize - 1;
    }
    else {
      nread = (int)upload_size;
    }
    byte_count = (size_t)nread;
    upload_size = 0;
  }
  else {
    byte_count = (size_t)upload_size;
  }

  memset(msg, 0, msgsize);
  msg->word_count = SMB_WC_WRITE_ANDX;
  msg->andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg->fid = smb_swap16(req->fid);
  msg->offset = smb_swap32((unsigned int) offset);
  msg->offset_high = smb_swap32((unsigned int) (offset >> 32));
  msg->data_length = smb_swap16((unsigned short) byte_count);
  msg->data_offset = smb_swap16((unsigned short)
                                  (msgsize - sizeof(unsigned int)));
  msg->byte_count = smb_swap16((unsigned short) (byte_count + 1));

  if(smbc->sig_required) {
    /* Read the file and append it here - this is necessary in order to have
     * the full message for signing correctly */
    conn->data->req.upload_fromhere = conn->data->state.ulbuf + msgsize;
    if(nread > 0) {
      result = Curl_fillreadbuffer(conn, nread, &nread);
      if(result && result != CURLE_AGAIN) {
        return result;
      }
    }

    /* If we read less than expected, must update the byte count */
    if(byte_count != (unsigned int)nread) {
      byte_count = (size_t)nread;
      msg->data_length = smb_swap16((unsigned short) byte_count);
      msg->byte_count = smb_swap16((unsigned short) (byte_count + 1));
    }

    smb_format_message(conn, &msg->h, SMB_COM_WRITE_ANDX,
                       msgsize - sizeof(msg->h) + (size_t)byte_count);

    /* sign the full message */
    result = smb_sign(conn, &conn->proto.smbc, msgsize + nread
                                               - sizeof(struct smb_header));
    if(result) {
      return result;
    }
  }
  else {
    smb_format_message(conn, &msg->h, SMB_COM_WRITE_ANDX,
                       msgsize - sizeof(msg->h) + (size_t)byte_count);
  }

  return smb_send(conn, msgsize + nread, (size_t) upload_size);
}

static CURLcode smb2_send_write(struct connectdata* conn)
{
  CURLcode result;
  struct smb2_write_request request;
  memset(&request, 0, sizeof(request));

  struct smb_conn * smbc = &conn->proto.smbc;
  uint32_t remaining_bytes = (uint32_t) (conn->data->req.size
                                         - conn->data->req.bytecount);
  uint32_t upload_buffer_len;
  uint32_t max_length = smbc->max_write_size
                        - sizeof(struct smb2_write_request)
                        - sizeof(struct smb2_header)
                        - sizeof(struct net_bios_header);
  if(remaining_bytes > max_length) {
    upload_buffer_len = max_length;
  }
  else {
    upload_buffer_len = remaining_bytes;
  }

  char *bytes;
  bytes = malloc(upload_buffer_len);
  memset(bytes, 0, upload_buffer_len);

  conn->data->req.upload_fromhere = bytes;
  result = Curl_fillreadbuffer(conn, upload_buffer_len,
                               (size_t *)&upload_buffer_len);
  if(result) {
    free(bytes);
    return result;
  }

  smbc->expected_write = upload_buffer_len;

  request.structure_size = 49;
  request.data_offset = smb_swap16(sizeof(struct smb2_write_request)
                        + sizeof(struct smb2_header));
  request.length = smb_swap32(upload_buffer_len);
  request.offset = smb_swap64((uint64_t)conn->data->req.offset);
  memcpy(&request.file_id, &smbc->file_id, 16);
  request.remaining_bytes = smb_swap32(remaining_bytes - upload_buffer_len);

  size_t offset = sizeof(struct net_bios_header);
  result = smb2_compose_message(conn, SMB2_COM_WRITE, &request,
                                sizeof(struct smb2_write_request), bytes,
                                upload_buffer_len, 256, &offset, NOT_COMPOUND);
  if(result)
    return result;

  return smb2_send_message(conn, offset - sizeof(struct net_bios_header));
}

static CURLcode smb_send_delete(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_delete msg;
  size_t byte_count;
  char *bytes;
  char *p;
  unsigned char *utf16;
  size_t utf16len;

  /* reject the command if it has no path or there's \ on the end of path */
  if(strlen(req->path) == 0) {
    failf(conn->data, "No path specified");
    return CURLE_URL_MALFORMAT;
  }
  if(strcmp(req->path + strlen(req->path) - 1, "\\") == 0) {
    failf(conn->data, "Path does not point to a file");
    return CURLE_URL_MALFORMAT;
  }

  /* Convert path to unicode */
  utf16 = malloc((strlen(req->path) + 1) * 2);
  if(!utf16)
    return CURLE_OUT_OF_MEMORY;
  utf16len = smb_utf8_to_utf16le((unsigned char *)req->path, utf16);

  /* Ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16len + 1;
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header)- sizeof(struct smb_delete)) {
    free(utf16);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* Set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_DELETE;
  msg.search_attributes = SMB_NO_SEARCH_ATT;

  /* Construct bytes */
  msg.byte_count = smb_swap16((unsigned short)byte_count);
  memset(bytes, 0, byte_count + 1);
  p[0] = SMB_BUFFER_FORMAT_ASCII;
  p++;
  memcpy(p, utf16, utf16len);

  free(utf16);

  return smb_send_message(conn, SMB_COM_DELETE, &msg,
      sizeof(msg), bytes, byte_count);

}

static CURLcode smb_send_rename(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_rename msg;
  size_t utf16from_len, utf16to_len, byte_count;
  char *to;
  char *bytes;
  char *p;
  unsigned char *utf16from;
  unsigned char *utf16to;

  /* reject the command if it has no path or there's \ on the end of path */
  if(strlen(req->path) == 0) {
    failf(conn->data, "No path specified");
    return CURLE_URL_MALFORMAT;
  }
  if(strcmp(req->path + strlen(req->path) - 1, "\\") == 0) {
    failf(conn->data, "Path does not point to a file");
    return CURLE_URL_MALFORMAT;
  }

  /* convert source (from) path to unicode */
  utf16from = malloc((strlen(req->path) + 1) * 2);
  if(!utf16from)
    return CURLE_OUT_OF_MEMORY;
  utf16from_len = smb_utf8_to_utf16le((unsigned char *)req->path, utf16from);

  /* convert destination (to) path to unicode */
  to = malloc(strlen(req->custom_params) + strlen(req->path) + 1);
  if(!to) {
    free(utf16from);
    return CURLE_OUT_OF_MEMORY;
  }
  memcpy(to, req->path, strlen(req->path) + 1);
  p = strrchr(to, '\\');
  if(!p)
    strcpy(to, req->custom_params);
  else
    strcpy(p + 1, req->custom_params);
  utf16to = malloc((strlen(to) + 1) * 2);
  if(!utf16to) {
    free(utf16from);
    free(to);
    return CURLE_OUT_OF_MEMORY;
  }
  utf16to_len = smb_utf8_to_utf16le((unsigned char *)to, utf16to);
  free(to);

  /* Ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16from_len + utf16to_len + 3;
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_rename)) {
    free(utf16from);
    free(utf16to);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16from);
    free(utf16to);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* Set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_RENAME;
  msg.search_attributes = SMB_SEARCH_ATT_H_S;

  /* Construct bytes */
  msg.byte_count = smb_swap16((unsigned short)byte_count);
  memset(bytes, 0, byte_count + 1);
  p[0] = SMB_BUFFER_FORMAT_ASCII;
  p++;
  MSGCATLEN(utf16from, utf16from_len);
  p[0] = SMB_BUFFER_FORMAT_ASCII;
  p += 2; /* one byte of padding */
  MSGCATLEN(utf16to, utf16to_len);

  free(utf16from);
  free(utf16to);

  return smb_send_message(conn, SMB_COM_RENAME, &msg, sizeof(msg),
                          bytes, byte_count);

}

static CURLcode smb_send_mkdir(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_mkdir msg;
  size_t byte_count, utf16len;
  char *name;
  char *p;
  char *bytes;
  unsigned char *utf16;

  /* reject the command if there's no \ on the end of path */
  if(strlen(req->path) != 0) {
    if(strcmp(req->path + strlen(req->path) - 1, "\\") != 0) {
      failf(conn->data, "Path should not point to a file");
      return CURLE_URL_MALFORMAT;
    }
  }

  name = malloc(strlen(req->custom_params) + strlen(req->path) + 1);
  if(!name)
    return CURLE_OUT_OF_MEMORY;

  /* construct path */
  /* ensure full path if not directly on the share */
  if(req->path)
    snprintf(name, strlen(req->custom_params) + strlen(req->path) + 1, "%s%s",
             req->path, req->custom_params);
  else
    strcpy(name, req->custom_params);

  /* Convert path to unicode */
  utf16 = malloc((strlen(name) + 1) * 2);
  if(!utf16) {
    free(name);
    return CURLE_OUT_OF_MEMORY;
  }
  utf16len = smb_utf8_to_utf16le((unsigned char *)name, utf16);
  free(name);

  /* Ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16len + 1;
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_mkdir)) {
    free(utf16);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* Set Parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_CREATE_DIRECTORY;

  /* Construct bytes */
  msg.byte_count = smb_swap16((unsigned short)byte_count);
  memset(bytes, 0, byte_count + 1);
  p[0] = SMB_BUFFER_FORMAT_ASCII;
  p++;
  MSGCATLEN(utf16, utf16len);

  free(utf16);
  return smb_send_message(conn, SMB_COM_CREATE_DIRECTORY, &msg,
                          sizeof(msg), bytes, byte_count);
}

static CURLcode smb_send_deldir(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_deldir msg;
  size_t byte_count, utf16len;
  unsigned char *utf16;
  char *p;
  char *bytes;

  /* reject the command if it has no path or there's \ on the end of path */
  if(strlen(req->path) == 0) {
    failf(conn->data, "No path specified");
    return CURLE_URL_MALFORMAT;
  }
  if(strcmp(req->path + strlen(req->path) - 1, "\\") == 0) {
    failf(conn->data, "Path does not point to a directory");
    return CURLE_URL_MALFORMAT;
  }

  /* Convert path to unicode */
  utf16 = malloc((strlen(req->path) + 1) * 2);
  if(!utf16)
    return CURLE_OUT_OF_MEMORY;
  utf16len = smb_utf8_to_utf16le((unsigned char *)req->path, utf16);

  /* Ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16len + 1;
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_mkdir)) {
    free(utf16);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* Set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_DELETE_DIRECTORY;

  /* Construct bytes */
  msg.byte_count = smb_swap16((unsigned short)byte_count);
  memset(bytes, 0, byte_count + 1);
  p[0] = SMB_BUFFER_FORMAT_ASCII;
  p++;
  MSGCATLEN(utf16, utf16len);

  free(utf16);

  return smb_send_message(conn, SMB_COM_DELETE_DIRECTORY, &msg, sizeof(msg),
                          bytes, byte_count);
}

static CURLcode smb_send_move(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_rename msg;
  size_t utf16from_len, utf16to_len, byte_count;
  char *to;
  char *bytes;
  char *p;
  char *slash;
  unsigned char *utf16from;
  unsigned char *utf16to;

  /* reject the command if it has:
   * no path/custom param
   * \ on the end of path
   * no \ on the end of custom param */
  if(!req->path || !req->custom_params) {
    failf(conn->data, "No path or custom parameters specified");
    return CURLE_URL_MALFORMAT;
  }
  if(strcmp(req->path + strlen(req->path) - 1, "\\") == 0 ||
     strcmp(req->custom_params + strlen(req->custom_params) - 1, "/") != 0) {
    failf(conn->data, "Invalid path/custom parameter");
    return CURLE_URL_MALFORMAT;
  }

  slash = req->custom_params;
  for(; *slash; slash++) {
    if(*slash == '/')
      *slash = '\\';
  }

  /* convert source (from) path to unicode */
  utf16from = malloc((strlen(req->path) + 1) * 2);
  if(!utf16from)
    return CURLE_OUT_OF_MEMORY;
  utf16from_len = smb_utf8_to_utf16le((unsigned char *)req->path, utf16from);

  /* construct destination (to) path */
  to = calloc(strlen(req->custom_params) + strlen(req->path) + 1,
              sizeof(char));
  if(!to) {
    free(utf16from);
    return CURLE_OUT_OF_MEMORY;
  }
  memcpy(to, req->custom_params, strlen(req->custom_params) + 1);
  p = strrchr(req->path, '\\');
  if(p) {
    p++;
    memcpy(to + strlen(to), p, strlen(p) + 1);
  }
  else
    memcpy(to + strlen(to), req->path, strlen(req->path));

  /* convert destination (to) path to unicode */
  utf16to = malloc((strlen(to) + 1) * 2);
  if(!utf16to) {
    free(utf16from);
    free(to);
    return CURLE_OUT_OF_MEMORY;
  }
  utf16to_len = smb_utf8_to_utf16le((unsigned char *)to, utf16to);
  free(to);

  /* Ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16from_len + utf16to_len + 3;
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_rename)) {
    free(utf16from);
    free(utf16to);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16from);
    free(utf16to);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* Set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_RENAME;
  msg.search_attributes = SMB_SEARCH_ATT_H_S;

  /* Construct bytes */
  msg.byte_count = smb_swap16((unsigned short)byte_count);
  memset(bytes, 0, byte_count + 1);
  p[0] = SMB_BUFFER_FORMAT_ASCII;
  p++;
  MSGCATLEN(utf16from, utf16from_len);
  p[0] = SMB_BUFFER_FORMAT_ASCII;
  p += 2; /* one byte of padding*/
  MSGCATLEN(utf16to, utf16to_len);

  free(utf16from);
  free(utf16to);

  return smb_send_message(conn, SMB_COM_RENAME, &msg, sizeof(msg), bytes,
                          byte_count);
}

static CURLcode smb_send_file_name(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_trans2 msg;
  size_t byte_count, utf16len;
  unsigned short info_level;
  unsigned char *utf16;
  char *bytes;
  char *p;

  /* reject the command if it has no path */
  if(strlen(req->path) == 0) {
    failf(conn->data, "No path specified");
    return CURLE_URL_MALFORMAT;
  }

  /* Convert path to unicode */
  utf16 = malloc((strlen(req->path) + 1) * 2);
  if(!utf16)
    return CURLE_OUT_OF_MEMORY;
  utf16len = smb_utf8_to_utf16le((unsigned char *)req->path, utf16);

  /* Ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16len + 11; /* 5B pad, 2B info level, 4B reserved */
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_trans2)) {
    free(utf16);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* Set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_TRANS2;
  msg.total_parameter_count = smb_swap16((unsigned short)(utf16len + 6));
  msg.total_data_count = SMB_NO_TDC_TRANS2;
  msg.max_parameter_count = SMB_MPC_TRANS2_QUERY_PATH_INFO;
  msg.max_data_count = SMB_MDC_TRANS2;
  msg.max_setup_count = SMB_NO_MSC_TRANS2;
  msg.flags = SMB_TRANS2_FLAGS_NONE;
  msg.timeout = 0x00000000;
  msg.parameter_count =  smb_swap16((unsigned short) (utf16len + 6));
  msg.parameter_offset = SMB_PO_TRANS2;
  msg.data_count = SMB_NO_DC_TRANS2;
  msg.data_offset = smb_swap16((unsigned short)(utf16len + 6));
  msg.setup_count = SMB_ONE_SETUP_TRANS2;
  msg.setup = SMB_SETUP_TRANS2_QUERY_PATH_INFO;

  /* Construct bytes */
  msg.byte_count = (unsigned short)byte_count;
  memset(bytes, 0, byte_count + 1);
  p += 3; /* 3 bytes padding */
  info_level = SMB_QUERY_FILE_ALT_NAME_INFO;
  p[0] = (char)(info_level & 0xff);
  p++;
  p[0] = (char)((info_level>>8) & 0xff);
  p++;
  p += 4; /* 4 bytes reserved */
  MSGCATLEN(utf16, utf16len);

  free(utf16);

  return smb_send_message(conn, SMB_COM_TRANSACTION2, &msg, sizeof(msg),
                          bytes, byte_count);
}

static CURLcode smb_send_file_info(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_trans2 msg;
  size_t byte_count, utf16len;
  unsigned short info_level;
  unsigned char *utf16;
  char *bytes;
  char *p;

  /* reject the command if it has no path */
  if(strlen(req->path) == 0) {
    failf(conn->data, "No path specified");
    return CURLE_URL_MALFORMAT;
  }

  /* convert path to unicode */
  utf16 = malloc((strlen(req->path) + 1) * 2);
  if(!utf16)
    return CURLE_OUT_OF_MEMORY;
  utf16len = smb_utf8_to_utf16le((unsigned char *) req->path, utf16);

  /* ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16len + 11; /* 5B pad, 2B info level, 4B reserved */
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_trans2)) {
    free(utf16);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* Set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_TRANS2;
  msg.total_parameter_count = smb_swap16((unsigned short) (byte_count - 3));
  msg.total_data_count = SMB_NO_TDC_TRANS2;
  msg.max_parameter_count = SMB_MPC_TRANS2_QUERY_PATH_INFO;
  msg.max_data_count = SMB_MDC_TRANS2;
  msg.max_setup_count = SMB_NO_MSC_TRANS2;
  msg.flags = SMB_TRANS2_FLAGS_NONE;
  msg.timeout = 0x00000000;
  msg.parameter_count = smb_swap16((unsigned short) (byte_count - 3));
  msg.parameter_offset = SMB_PO_TRANS2;
  msg.data_count = SMB_NO_DC_TRANS2;
  msg.data_offset = smb_swap16((unsigned short)
                                       (SMB_PO_TRANS2 + byte_count - 3));
  msg.setup_count = SMB_ONE_SETUP_TRANS2;
  msg.setup = SMB_SETUP_TRANS2_QUERY_PATH_INFO;

  /* construct bytes */
  msg.byte_count = (unsigned short) byte_count;
  memset(bytes, 0, byte_count + 1);
  p += 3; /* 3 bytes padding */
  info_level = SMB_QUERY_FILE_ALL_INFO;
  p[0] = (char) (info_level & 0xff);
  p++;
  p[0] = (char) ((info_level >> 8) & 0xff);
  p++;
  p += 4; /* 4 bytes reserved */
  MSGCATLEN(utf16, utf16len);

  free(utf16);

  return smb_send_message(conn, SMB_COM_TRANSACTION2, &msg, sizeof(msg),
                          bytes, byte_count);
}

static CURLcode smb2_send_file_info(struct connectdata *conn,
                                    enum smb_req_state req_state)
{
  struct smb_request *req = conn->data->req.protop;
  unsigned char *bytes = NULL;
  size_t byte_count = 0;
  CURLcode result;

  /* if command has no path, or just \ then getting info of root directory */
  if(strlen(req->path) == 0 || strcmp(req->path, "\\") == 0) {
    req_state = SMB2_DIR_ALLINFO;
  }
  else {
    /* if req_state is SMB2_DIR_ALLINFO then failed to get info of path as a
     * file, attempting again as a dir, else need to check the path to
     * determine if its a file or directory, if path ends with \ its a dir */
    if(req_state != SMB2_DIR_ALLINFO) {
      req_state = (strcmp(req->path + strlen(req->path) - 1, "\\") ?
                   SMB_FILE_ALLINFO : SMB2_DIR_ALLINFO);
    }

    /* Convert path to utf16_le */
    bytes = malloc((strlen(req->path) + 1) * 2);
    if(!bytes) {
      return CURLE_OUT_OF_MEMORY;
    }
    byte_count = smb_utf8_to_utf16le((unsigned char *)req->path, bytes);
    byte_count -= 2; /* SMBv2 does not include the two null terminators */
  }

  size_t compound_offset = sizeof(struct net_bios_header);
  result = smb2_compose_create(conn, req_state, bytes, byte_count,
                               &compound_offset, FIRST_COMPOUND);
  if(result)
    return result;

  result = smb2_compose_close(conn, SMB_FILE_ALLINFO, &compound_offset,
                              LAST_COMPOUND);
  if(result)
    return result;

  return smb2_send_message(conn, compound_offset
                                 - sizeof(struct net_bios_header));
}

static CURLcode smb_send_find_first_ls(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_trans2 msg;
  size_t byte_count, utf16len;
  unsigned short parameter;
  unsigned char *utf16;
  char *bytes;
  char *path;
  char *p;

  /* reject the command if there's no \ on the end of path */
  if(strlen(req->path) != 0) {
    if(strcmp(req->path + strlen(req->path) - 1, "\\") != 0) {
      failf(conn->data, "Path should not point to a file");
      return CURLE_URL_MALFORMAT;
    }
  }

  /* construct path */
  if(req->custom_params) {
    path = malloc(strlen(req->path) + strlen(req->custom_params) + 1);
    snprintf(path, strlen(req->path) + strlen(req->custom_params) + 1, "%s%s",
             req->path, req->custom_params);
  }
  else {
    path = malloc(strlen(req->path) + strlen("*") + 1);
    snprintf(path, strlen(req->path) + strlen("*") + 1, "%s*", req->path);
  }

  /* convert path to unicode */
  utf16 = malloc((strlen(path) + 1) * 2);
  if(!utf16) {
    free(path);
    return CURLE_OUT_OF_MEMORY;
  }
  utf16len = smb_utf8_to_utf16le((unsigned char *)path, utf16);
  free(path);

  /* ensure bytes to be sent will not exceed maximum size */
  byte_count = utf16len + 15;
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_trans2)) {
    free(utf16);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* Set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_TRANS2;
  msg.total_parameter_count = smb_swap16((unsigned short)(byte_count - 3));
  msg.total_data_count = SMB_NO_TDC_TRANS2;
  msg.max_parameter_count = SMB_MPC_TRANS2_FIND_FIRST2;
  msg.max_data_count = SMB_MDC_TRANS2;
  msg.max_setup_count = SMB_NO_MSC_TRANS2;
  msg.flags = SMB_TRANS2_FLAGS_NONE;
  msg.timeout = 0x00000000;
  msg.parameter_count =  smb_swap16((unsigned short)(byte_count - 3));
  msg.parameter_offset = SMB_PO_TRANS2;
  msg.data_count = SMB_NO_DC_TRANS2;
  msg.data_offset = smb_swap16((unsigned short)
                               (SMB_PO_TRANS2 + byte_count - 3));
  msg.setup_count = SMB_ONE_SETUP_TRANS2;
  msg.setup = SMB_SETUP_TRANS2_FIND_FIRST2;

  /* construct bytes */
  msg.byte_count = (unsigned short)byte_count;
  memset(bytes, 0, byte_count + 1);
  p += 3; /* 3 bytes padding */
  /* search att */
  parameter = SMB_FILE_ATTRIBUTE_READONLY + SMB_FILE_ATTRIBUTE_HIDDEN +
              SMB_FILE_ATTRIBUTE_SYSTEM + SMB_FILE_ATTRIBUTE_DIRECTORY +
              SMB_FILE_ATTRIBUTE_ARCHIVE;
  p[0] = (char)(parameter & 0xff);
  p++;
  p[0] = (char)((parameter>>8) & 0xff);
  p++;
  /* search count */
  parameter = SMB_TRANS2_SEARCH_COUNT;
  p[0] = (char)(parameter & 0xff);
  p++;
  p[0] = (char)((parameter>>8) & 0xff);
  p++;
  /* flags */
  parameter = SMB_FIND_CLOSE_AT_EOS + SMB_FIND_RETURN_RESUME_KEYS;
  p[0] = (char)(parameter & 0xff);
  p++;
  p[0] = (char)((parameter>>8) & 0xff);
  p++;
  /* Info Level SMB_FIND_FILE_BOTH_DIRECTORY_INFO (0x0104) */
  parameter = SMB_FIND_FILE_BOTH_DIRECTORY_INFO;
  p[0] = (char)(parameter & 0xff);
  p++;
  p[0] = (char)((parameter>>8) & 0xff);
  p++;
  p += 4; /* Search Storage Type (blank) */
  MSGCATLEN(utf16, utf16len); /* File Name */

  free(utf16);

  return smb_send_message(conn, SMB_COM_TRANSACTION2, &msg, sizeof(msg),
                          bytes, byte_count);
}

static CURLcode smb2_send_create(struct connectdata *conn,
                                 enum smb_req_state req_state)
{
  struct smb_request * req = conn->data->req.protop;
  size_t byte_count;
  unsigned char *bytes;
  CURLcode result;

  if(strlen(req->path) != 0) {
    int endsWithSlash = strcmp(req->path + strlen(req->path) - 1, "\\") == 0;
    if(req_state == SMB_OPEN && endsWithSlash) {
      failf(conn->data, "Path should not point to a directory");
      return CURLE_URL_MALFORMAT;
    }
    else if(req_state == SMB_FINDFIRST && !endsWithSlash) {
      failf(conn->data, "Path should not point to a file");
      return CURLE_URL_MALFORMAT;
    }
  }

  /* Convert path to utf16_le */
  bytes = malloc((strlen(req->path) + 1) * 2);
  if(!bytes) {
    return CURLE_OUT_OF_MEMORY;
  }
  byte_count = (short) smb_utf8_to_utf16le((unsigned char *) req->path, bytes);
  byte_count -= 2; /* SMBv2 does not include the two null terminators */

  size_t offset = sizeof(struct net_bios_header);
  result = smb2_compose_create(conn, req_state, bytes, byte_count,
                               &offset, NOT_COMPOUND);
  if(result)
    return result;

  return smb2_send_message(conn, offset - sizeof(struct net_bios_header));
}

static CURLcode smb2_handle_create_resp(struct smb_conn* smbc, void *msg)
{
  struct smb2_create_response * response;
  response = msg;
  memcpy(&(smbc->file_id), &(response->file_id), 16);

  if(smbc->more_buf)
    Curl_safefree(smbc->more_buf);
  smbc->more_size = 0;

  return CURLE_OK;
}

static CURLcode smb2_send_read(struct connectdata* conn)
{
  struct smb2_read_request request;
  memset(&request, 0, sizeof(request));

  struct smb_conn * smbc = &conn->proto.smbc;
  uint32_t remaining_bytes = (uint32_t) (conn->data->req.size
                                         - conn->data->req.offset);
  uint32_t download_buffer_length;
  if(remaining_bytes >
      smbc->max_read_size - sizeof(struct smb2_read_response)) {
    download_buffer_length = smbc->max_read_size
                             - sizeof(struct smb2_read_response);
  }
  else {
    download_buffer_length = remaining_bytes;
  }

  request.structure_size = 49;
  request.length = smb_swap32(download_buffer_length);
  request.offset = smb_swap64((uint64_t) conn->data->req.offset);
  memcpy(&request.file_id, &conn->proto.smbc.file_id, 16);
  request.min_count = 1;
  request.remaining_bytes = smb_swap32(remaining_bytes
                                         - download_buffer_length);

  unsigned char *bytes;
  size_t bytes_len = 1;
  bytes = malloc(bytes_len);
  *bytes = 0;

  CURLcode result;
  size_t offset = sizeof(struct net_bios_header);
  result = smb2_compose_message(conn, SMB2_COM_READ, &request,
                              sizeof(struct smb2_read_request),
                              bytes, bytes_len, 256, &offset, NOT_COMPOUND);
  if(result)
    return result;

  return smb2_send_message(conn, offset - sizeof(struct net_bios_header));
}

static CURLcode smb2_send_query_directory(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb2_query_directory_request request;
  size_t byte_count = 0;
  unsigned char *bytes;
  CURLcode result;

  /* Set parameters */
  memset(&request, 0, sizeof(struct smb2_query_directory_request));
  request.structure_size = 33;
  request.file_info_class = SMB2_FILE_DIRECTORY_INFORMATION;
  memcpy(&(request.file_id), &(conn->proto.smbc.file_id), 16);

  /* construct unicode search pattern */
  if(req->custom_params) {
    bytes = malloc((strlen(req->custom_params) + 1) *2);
    if(!bytes) {
      return CURLE_OUT_OF_MEMORY;
    }
    byte_count = smb_utf8_to_utf16le(
      (unsigned char *)req->custom_params, bytes);
  }
  else {
    bytes = malloc(4);
    if(!bytes) {
      return CURLE_OUT_OF_MEMORY;
    }
    byte_count = smb_utf8_to_utf16le((unsigned char *)"*", bytes);
  }

  byte_count -= 2; /* SMBv2 does not include the two null terminators */

  request.file_name_offset = smb_swap16(sizeof(struct smb2_header)
                               + sizeof(struct smb2_query_directory_request));
  request.file_name_length = smb_swap16((unsigned short) byte_count);

  request.output_buffer_length = smb_swap32(conn->proto.smbc.max_transact_size
                               - sizeof(struct smb2_query_directory_response));

  size_t offset = sizeof(struct net_bios_header);
  result = smb2_compose_message(conn, SMB2_COM_QUERY_DIRECTORY, &request,
                       sizeof(struct smb2_query_directory_request), bytes,
                       byte_count, 286, &offset, NOT_COMPOUND);
  if(result)
    return result;
  return smb2_send_message(conn, sizeof(struct smb2_header)
                                 + sizeof(struct smb2_query_directory_request)
                                 + byte_count);
}

static CURLcode smb2_resp_query_directory(struct smb_conn *smbc, void *msg)
{
  struct smb2_query_directory_response * response;
  response = msg;

  if(response->output_buffer_length == 0)
    return CURLE_OK;

  if(smbc->more_buf)
    Curl_safefree(smbc->more_buf);

  smbc->more_buf = (char *) malloc(response->output_buffer_length);
  if(!smbc->more_buf)
    return CURLE_OUT_OF_MEMORY;

  uint32_t data_off = sizeof(struct net_bios_header)
                      + response->output_buffer_offset;
  memcpy(smbc->more_buf, (const char *)(msg + data_off),
         response->output_buffer_length);

  smbc->more_size = response->output_buffer_length;

  return CURLE_OK;
}

static CURLcode smb_send_find_next_ls(struct connectdata *conn)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb_trans2 msg;
  size_t byte_count;
  unsigned short parameter;
  char *bytes;
  char *p;

  /* ensure bytes to be sent will not exceed maximum size */
  byte_count = req->resume_filelen + 15;
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_trans2))
     return CURLE_FILESIZE_EXCEEDED;
  bytes = malloc(byte_count + 1);
  if(!bytes)
    return CURLE_OUT_OF_MEMORY;
  p = bytes;

  /* Set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_TRANS2;
  msg.total_parameter_count = smb_swap16((unsigned short)(byte_count - 3));
  msg.total_data_count = SMB_NO_TDC_TRANS2;
  msg.max_parameter_count = SMB_MPC_TRANS2_FIND_FIRST2;
  msg.max_data_count = SMB_MDC_TRANS2;
  msg.max_setup_count = SMB_NO_MSC_TRANS2;
  msg.flags = SMB_TRANS2_FLAGS_NONE;
  msg.timeout = 0x00000000;
  msg.parameter_count = smb_swap16((unsigned short)(byte_count - 3));
  msg.parameter_offset = SMB_PO_TRANS2;
  msg.data_count = SMB_NO_DC_TRANS2;
  msg.data_offset = smb_swap16((unsigned short)
                               (SMB_PO_TRANS2 + byte_count - 3));
  msg.setup_count = SMB_ONE_SETUP_TRANS2;
  msg.setup = SMB_SETUP_TRANS2_FIND_NEXT2;

  /* construct bytes */
  msg.byte_count = (unsigned short)byte_count;
  memset(bytes, 0, byte_count + 1);
  p += 3; /* 3 bytes padding */
  /* SID */
  p[0] = (char)(req->sid & 0xff);
  p++;
  p[0] = (char)((req->sid >> 8) & 0xff);
  p++;
  /* search count */
  p[0] = (char)(SMB_TRANS2_SEARCH_COUNT & 0xff);
  p++;
  p[0] = (char)((SMB_TRANS2_SEARCH_COUNT>>8) & 0xff);
  p++;
  /* Info Level SMB_FIND_FILE_BOTH_DIRECTORY_INFO (0x0104) */
  p[0] = (char)(SMB_FIND_FILE_BOTH_DIRECTORY_INFO & 0xff);
  p++;
  p[0] = (char)((SMB_FIND_FILE_BOTH_DIRECTORY_INFO>>8) & 0xff);
  p++;
  p += 4; /* resume key */
  /* flags */
  parameter = SMB_FIND_CLOSE_AT_EOS + SMB_FIND_RETURN_RESUME_KEYS +
              SMB_FIND_CONTINUE_FROM_LAST;
  p[0] = (char)(parameter & 0xff);
  p++;
  p[0] = (char)((parameter>>8) & 0xff);
  p++;
  MSGCATLEN(req->resume_file, req->resume_filelen); /* File Name */

  return smb_send_message(conn, SMB_COM_TRANSACTION2, &msg, sizeof(msg),
  bytes, byte_count);
}

static CURLcode smb_send_get_dfs_referral(struct connectdata *conn)
{
  CURLcode result;
  struct smb_conn *smbc = &conn->proto.smbc;
  struct smb_request *req = conn->data->req.protop;
  struct smb_trans2 msg;
  size_t byte_count;
  unsigned char *utf16;
  unsigned short ref_level;
  char *p;
  char *path;
  char *bytes;
  size_t pathlen, unilen;

  /* construct path */
  result = smb_construct_path(&path, &pathlen, conn->host.name, smbc->share,
                              req->path);
  if(result)
    return result;

  /* convert path to unicode */
  utf16 = malloc((pathlen + 1) * 2);
  if(!utf16) {
    free(path);
    return CURLE_OUT_OF_MEMORY;
  }
  unilen = smb_utf8_to_utf16le((unsigned char *)path, utf16);
  free(path);

  /* ensure bytes to be sent will not exceed maximum size */
  byte_count = unilen + 5; /* path + 2 bytes max refer lvl + pad */
  if(byte_count > conn->data->set.upload_buffer_size
                  - sizeof(struct smb_header) - sizeof(struct smb_trans2)) {
    free(utf16);
    return CURLE_FILESIZE_EXCEEDED;
  }
  bytes = malloc(byte_count + 1);
  if(!bytes) {
    free(utf16);
    return CURLE_OUT_OF_MEMORY;
  }
  p = bytes;

  /* set parameters */
  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_TRANS2;
  msg.total_parameter_count = smb_swap16((unsigned short)(byte_count - 3));
  msg.total_data_count = SMB_NO_TDC_TRANS2;
  msg.max_parameter_count = SMB_MPC_TRANS2_DFS;
  msg.max_data_count = SMB_MDC_TRANS2;
  msg.max_setup_count = SMB_NO_MSC_TRANS2;
  msg.flags = SMB_TRANS2_FLAGS_NONE;
  msg.timeout = 0x00000000;
  msg.parameter_count = smb_swap16((unsigned short)(byte_count - 3));
  msg.parameter_offset = SMB_PO_TRANS2;
  msg.data_count = SMB_NO_DC_TRANS2;
  msg.data_offset = smb_swap16((unsigned short)
                               (SMB_PO_TRANS2 + byte_count - 3));
  msg.setup_count = SMB_ONE_SETUP_TRANS2;
  msg.setup = SMB_SETUP_TRANS2_GET_DFS;

  /* construct bytes */
  msg.byte_count = (unsigned short)byte_count;
  memset(bytes, 0, byte_count);
  p += 3; /* 3 bytes padding */
  /* Referral Level v2 */
  ref_level = 0x0002;
  p[0] = (char)(ref_level & 0xff);
  p++;
  p[0] = (char)((ref_level>>8) & 0xff);
  p++;
  MSGCATLEN(utf16, unilen); /* path */

  free(utf16);

  return smb_send_message(conn, SMB_COM_TRANSACTION2, &msg, sizeof(msg),
  bytes, byte_count);
}

static CURLcode smb2_send_get_dfs_referral(struct connectdata *conn)
{
  if(!conn->proto.smbc.using_dfs)
    return CURLE_OK;

  CURLcode result;
  struct smb_conn *smbc = &conn->proto.smbc;
  struct smb_request *req = conn->data->req.protop;
  struct smb2_ioctl_request request;
  memset(&request, 0, sizeof(request));

  /* construct path */
  char *path;
  size_t pathlen;
  unsigned char *bytes;
  size_t byte_count;

  result = smb_construct_path(&path, &pathlen, conn->host.name, smbc->share,
                              req->path);
  if(result)
    return result;

  /* Convert path to utf16_le */
  bytes = malloc(2 + ((pathlen + 1) * 2)); /* +2 for MaxReferralLevel */
  if(!bytes)
    return CURLE_OUT_OF_MEMORY;
  /* MaxReferralLevel */
  short level4 = smb_swap16(0x0004);
  memcpy(bytes, &level4, 2);

  byte_count = smb_utf8_to_utf16le((unsigned char *)path, bytes + 2);
  /* byte_count includes two unrequired null terminators,
   * and needs to include the 2 byte MaxReferralLevel,
   * so the returned count is actually correct */
  free(path);

  request.structure_size = 57;
  request.ctl_code = FSCTL_DFS_GET_REFERRALS;
  memset(&request.file_id, 0xFF, 16);
  request.input_offset = smb_swap32(sizeof(struct smb2_header)
                         + sizeof(struct smb2_ioctl_request));
  request.input_count = smb_swap32((uint32_t)byte_count);
  request.output_offset = smb_swap32(sizeof(struct smb2_header)
                                     + sizeof(struct smb2_ioctl_request)
                                     + byte_count);
  request.max_output_response = smb_swap32(conn->proto.smbc.max_transact_size
                                         - sizeof(struct smb2_ioctl_response));
  request.flags = SMB2_0_IOCTL_IS_FSCTL;

  size_t offset = sizeof(struct net_bios_header);
  result = smb2_compose_message(conn, SMB2_COM_IOCTL, &request,
                                sizeof(request), bytes, byte_count, 256,
                                &offset, NOT_COMPOUND);
  if(result)
    return result;
  return smb2_send_message(conn, sizeof(struct smb2_header) + sizeof(request)
                                 + byte_count);
}

static CURLcode smb_send_and_recv(struct connectdata *conn, void **msg)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  CURLcode result;

  /* Check if there is data in the transfer buffer */
  if(!smbc->send_size && smbc->upload_size) {
    size_t nread = smbc->upload_size > conn->data->set.upload_buffer_size ?
      conn->data->set.upload_buffer_size :
      smbc->upload_size;
    conn->data->req.upload_fromhere = conn->data->state.ulbuf;
    result = Curl_fillreadbuffer(conn, nread, &nread);
    if(result && result != CURLE_AGAIN)
      return result;
    if(!nread)
      return CURLE_OK;

    smbc->upload_size -= nread;
    smbc->send_size = nread;
    smbc->sent = 0;
  }

  /* Check if there is data to send */
  if(smbc->send_size) {
    result = smb_flush(conn);
    if(result)
      return result;
  }

  /* Check if there is still data to be sent */
  if(smbc->send_size || smbc->upload_size)
    return CURLE_AGAIN;

  return smb_recv_message(conn, msg);
}

static void smb_parse_attributes(unsigned int attributeFlags,
                                 char *buf, size_t *buf_orig_len)
{
  unsigned int attributeCmp[6] = { 0x00000001, 0x00000002, 0x00000004,
                                   0x00000010, 0x00000020, 0x00000080 };
  size_t buf_len = *buf_orig_len;

  if(attributeFlags & attributeCmp[0]) { /* Read-Only */
    SMBBUFWRITE("R", strlen("R"));
  }
  if(attributeFlags & attributeCmp[1]) { /* Hidden */
    SMBBUFWRITE("H", strlen("H"));
  }
  if(attributeFlags & attributeCmp[2]) { /* System */
    SMBBUFWRITE("S", strlen("S"));
  }
  if(attributeFlags & attributeCmp[3]) { /* Directory */
    SMBBUFWRITE("D", strlen("D"));
  }
  if(attributeFlags & attributeCmp[4]) { /* Archive */
    SMBBUFWRITE("A", strlen("A"));
  }
  if(attributeFlags & attributeCmp[5]) { /* Normal */
    SMBBUFWRITE("N", strlen("N"));
  }
  *buf_orig_len = buf_len;
}

static char *smb_parse_timestamp(uint64_t tmp_time)
{
  time_t filetime;
  tmp_time = tmp_time / 10000000;
  filetime = (time_t)(tmp_time - EPOCH_DIFF);
  return ctime(&filetime);
}

static CURLcode smb_parse_resp_string(void *msg, int offset, size_t length,
                                      unsigned  char **utf8_target,
                                      size_t *utf8_length,
                                      struct connectdata *conn)
{
  unsigned char *utf16_target;

  /* read target from response */
  utf16_target = malloc(length);
  if(!utf16_target)
    return CURLE_OUT_OF_MEMORY;

  memcpy(utf16_target, (const char *) msg + offset + 4, length);
  /* convert from UTF-16LE target to UTF-8 */
  *utf8_target = malloc(length);
  if(!utf8_target) {
    free(utf16_target);
    return CURLE_OUT_OF_MEMORY;
  }
  *utf8_length = smb_utf16le_to_utf8(utf16_target, length, *utf8_target);
  free(utf16_target);
  if(*utf8_length == 0) {
    failf(conn->data, "Unable to convert encoding in response");
    free(utf8_target);
    return CURLE_RECV_ERROR;
  }

  return CURLE_OK;
}

static size_t smb_get_unicode_length(unsigned char *buf)
{
  size_t length = 0;
  while(*buf) {
    length += 2;
    buf += 2;
  }

  return length;
}

/* Convert a utf16_le response string (must be null terminated) to utf8 */
static CURLcode smb2_parse_resp_string(unsigned char *resp_src,
                                     unsigned char **utf8_dest,
                                     size_t *utf8_dest_length)
{
  size_t length = smb_get_unicode_length(resp_src);
  *utf8_dest = calloc(length, sizeof(char));
  if(!utf8_dest) {
    return CURLE_OUT_OF_MEMORY;
  }
  /* convert from UTF-16LE to UTF-8 */
  *utf8_dest_length = smb_utf16le_to_utf8(resp_src, length, *utf8_dest);
  if(*utf8_dest_length == 0) {
    free(utf8_dest);
    return CURLE_RECV_ERROR;
  }

  return CURLE_OK;
}

static enum smb_req_state smb_resp_tree_connect(struct smb_request *req)
{
  /* work out what the next command should be */
  /* https://msdn.microsoft.com/en-us/library/ee441940.aspx */
  if(!req->custom) {
    return SMB_OPEN;
  }
  else if(!strcasecmp("del", req->custom)) {
    return SMB_DELETE;
  }
  else if(!strcasecmp("rename", req->custom)) {
    return SMB_RENAME;
  }
  else if(!strcasecmp("mkdir", req->custom)) {
    return SMB_MKDIR;
  }
  else if(!strcasecmp("deldir", req->custom)) {
    return SMB_DELDIR;
  }
  else if(!strcasecmp("move", req->custom)) {
    return SMB_MOVE;
  }
  else if(!strcasecmp("info", req->custom)) {
    return SMB_FILE_SHORTNAME;
  }
  else if(!strcasecmp("ls", req->custom)) {
    return SMB_FINDFIRST;
  }
  else if(!strcasecmp("checkdfs", req->custom)) {
    return SMB_CHECKDFS;
  }
  else {
    req->result = CURLE_URL_MALFORMAT;
    return SMB_CLOSE;
  }
}

/*
 * Convert a timestamp from the Windows world (100 nsec units from 1 Jan 1601)
 * to Posix time. Cap the output to fit within a time_t.
 */
static void get_posix_time(time_t *out, curl_off_t timestamp)
{
  timestamp -= 116444736000000000;
  timestamp /= 10000000;
#if SIZEOF_TIME_T < SIZEOF_CURL_OFF_T
  if(timestamp > TIME_T_MAX)
    *out = TIME_T_MAX;
  else if(timestamp < TIME_T_MIN)
    *out = TIME_T_MIN;
  else
#endif
  *out = (time_t) timestamp;
}

static enum smb_req_state smb_resp_open(struct connectdata *conn,
                                        struct smb_request *req, void *msg) {
  conn->data->req.offset = 0;
  if(conn->data->set.upload) {
    conn->data->req.size = conn->data->state.infilesize;
    Curl_pgrsSetUploadSize(conn->data, conn->data->req.size);
    return SMB_UPLOAD;
  }
  else {
    const struct smb_nt_create_response *smb_m;
    smb_m = (const struct smb_nt_create_response*) msg;
    conn->data->req.size = smb_swap64((curl_off_t)smb_m->end_of_file);
    if(conn->data->req.size < 0) {
      req->result = CURLE_WEIRD_SERVER_REPLY;
      return SMB_CLOSE;
    }
    else {
      Curl_pgrsSetDownloadSize(conn->data, conn->data->req.size);
      if(conn->data->set.get_filetime)
        get_posix_time(&conn->data->info.filetime, smb_m->last_change_time);
      return SMB_DOWNLOAD;
    }
  }
}

static enum smb_req_state smb2_handle_create_open_resp(
    struct connectdata* conn, void *msg)
{
  conn->data->req.offset = 0;
  if(conn->data->set.upload) {
    if(conn->data->state.infilesize == 0)
      return SMB_CLOSE;
    conn->data->req.size = conn->data->state.infilesize;
    Curl_pgrsSetUploadSize(conn->data, conn->data->req.size);
    return SMB_UPLOAD;
  }
  struct smb2_create_response * resp;
  resp = msg;
  conn->data->req.size = (curl_off_t)smb_swap64(resp->end_of_file);
  Curl_pgrsSetDownloadSize(conn->data, conn->data->req.size);
  return SMB_DOWNLOAD;
}

static enum smb_req_state smb_resp_download(struct connectdata *conn,
                                            struct smb_conn *smbc,
                                            struct smb_request *req, void *msg,
                                            CURLcode *result) {
  unsigned short len, off;

  len = Curl_read16_le(((unsigned char *) msg) +
                       sizeof(struct smb_header) + 11);
  off = Curl_read16_le(((unsigned char *) msg) +
                       sizeof(struct smb_header) + 13);
  if(len > 0) {
    if(off + sizeof(unsigned int) + len > smbc->got) {
      failf(conn->data, "Invalid input packet");
      *result = CURLE_RECV_ERROR;
    }
    else
      *result = Curl_client_write(conn, CLIENTWRITE_BODY,
                                 (char *)msg + off + sizeof(unsigned int),
                                 len);
    if(*result) {
      req->result = *result;
      return SMB_CLOSE;
    }
  }
  conn->data->req.bytecount += len;
  conn->data->req.offset += len;
  Curl_pgrsSetDownloadCounter(conn->data, conn->data->req.bytecount);
  return (len < MAX_PAYLOAD_SIZE) ? SMB_CLOSE : SMB_DOWNLOAD;
}

static enum smb_req_state smb2_handle_read_resp(struct connectdata* conn,
                                                struct smb_conn* smbc,
                                                struct smb_request* req,
                                                void *msg) {
  struct smb2_read_response * response;
  response = msg;
  uint32_t length = response->data_length;
  unsigned short offset = response->data_offset +
      sizeof(struct net_bios_header);

  CURLcode result;
  if(length > 0) {
    if(offset + length > smbc->got) {
      failf(conn->data, "Invalid input packet");
      result = CURLE_RECV_ERROR;
    }
    else
      result = Curl_client_write(conn, CLIENTWRITE_BODY,
                                  (char *) msg + offset, length);
    if(result) {
      req->result = result;
      return SMB_CLOSE;
    }
  }
  conn->data->req.bytecount += length;
  conn->data->req.offset += length;
  Curl_pgrsSetDownloadCounter(conn->data, conn->data->req.bytecount);
  return (conn->data->req.bytecount == conn->data->req.size)
         ? SMB_CLOSE : SMB_DOWNLOAD;
}

static enum smb_req_state smb_resp_upload(struct connectdata *conn,
                                          void *msg) {
  unsigned short len;

  len = Curl_read16_le(((unsigned char *) msg) +
                       sizeof(struct smb_header) + 5);
  conn->data->req.bytecount += len;
  conn->data->req.offset += len;
  Curl_pgrsSetUploadCounter(conn->data, conn->data->req.bytecount);
  if(conn->data->req.bytecount >= conn->data->req.size)
    return SMB_CLOSE;
  else
    return SMB_UPLOAD;
}

static enum smb_req_state smb2_handle_write_resp(struct connectdata* conn,
                                                struct smb_conn* smbc,
                                                struct smb_request* req,
                                                void *msg) {
  struct smb2_write_response * response;
  response = msg;
  uint32_t length = response->count;
  conn->data->req.bytecount += length;
  conn->data->req.offset += length;

  if(length != smbc->expected_write) {
    failf(conn->data, "Server failed to write expected length");
    req->result = CURLE_WRITE_ERROR;
    return SMB_CLOSE;
  }

  Curl_pgrsSetUploadCounter(conn->data, conn->data->req.bytecount);
  if(conn->data->req.bytecount >= conn->data->req.size)
    return SMB_CLOSE;
  else
    return SMB_UPLOAD;
}

static enum smb_req_state smb_resp_file_shortname(struct connectdata *conn,
                                                  struct smb_conn *smbc,
                                                  struct smb_request *req,
                                                  void *msg,
                                                  CURLcode *result) {
  unsigned short off;
  char *buf = smbc->write_buf;
  char filename[(MAX_SHORTNAME_SIZE*2) + 1];
  unsigned int filelen, i;
  size_t buf_len = 0;

  memset(filename, 0, (MAX_SHORTNAME_SIZE*2) + 1);
  off = Curl_read16_le(((unsigned char *) msg) +
                       sizeof(struct smb_header) + 15);
  filelen = Curl_read32_le((unsigned char *) msg + off + 4);
  SMBBUFWRITE("shortname: \t", strlen("shortname: \t"));
  memcpy(filename, (unsigned char *) msg + off + 8, filelen);
  for(i = 0; i <= filelen; i = i + 2) {
    filename[i/2] = filename[i];
  }
  SMBBUFWRITE(filename, strlen(filename));
  SMBBUFWRITE("\n", strlen("\n"));

  if(buf_len > 0) {
    if(off + sizeof(unsigned int) + filelen + 4 > smbc->got) {
      failf(conn->data, "Invalid input packet");
      *result = CURLE_RECV_ERROR;
    }
    else {
      *result = Curl_client_write(conn, CLIENTWRITE_BODY, smbc->write_buf,
                                  buf_len);
    }
    if(*result) {
      req->result = *result;
      return SMB_TREE_DISCONNECT;
    }
  }
  return SMB_FILE_ALLINFO;
}

static enum smb_req_state smb_resp_file_allinfo(struct connectdata *conn,
                                                struct smb_conn *smbc,
                                                struct smb_request *req,
                                                void *msg, CURLcode *result) {
  unsigned short len, off;
  char *buf = smbc->write_buf;
  char *datetime;
  unsigned int attributeFlags;
  unsigned int attributeCmp[6] = { 0x00000001, 0x00000002, 0x00000004,
                             0x00000010, 0x00000020, 0x00000080 };
  uint64_t tmp_time = 0;
  unsigned char fsize_string[MAX_BUFFER_LEN_64 + 1] = { 0 };
  unsigned long long filesize;
  size_t buf_len = 0;

  /* handle response here */
  len = Curl_read16_le(((unsigned char *) msg) +
                       sizeof(struct smb_header) + 13);
  off = Curl_read16_le(((unsigned char *) msg) +
                       sizeof(struct smb_header) + 15);

  /* file size (EndOfFile) */
  filesize = Curl_read64_le(((unsigned char *)msg + off +
                             sizeof(unsigned int) + 48));
  snprintf((char *)fsize_string, MAX_BUFFER_LEN_64, "%lld", filesize);
  SMBBUFWRITE("file_size: \t", strlen("file_size: \t"));
  SMBBUFWRITE((const char *)fsize_string, strlen((const char *)fsize_string));
  SMBBUFWRITE("\n", strlen("\n"));

  /* read in times & write to buffer */

  /* time created */
  tmp_time = Curl_read64_le(((unsigned char *)msg + off +
                             sizeof(unsigned int)));
  SMBBUFWRITE("create_time: \t", strlen("create_time: \t"));
  datetime = smb_parse_timestamp(tmp_time);
  SMBBUFWRITE(datetime, strlen(datetime));

  /* last accessed */
  tmp_time = Curl_read64_le(((unsigned char *)msg + off +
                             sizeof(unsigned int) + 8));
  SMBBUFWRITE("access_time: \t", strlen("access_time: \t"));
  datetime = smb_parse_timestamp(tmp_time);
  SMBBUFWRITE(datetime, strlen(datetime));

  /* last written */
  tmp_time = Curl_read64_le(((unsigned char *)msg + off +
                             sizeof(unsigned int) + 16));
  SMBBUFWRITE("write_time: \t", strlen("write_time: \t"));
  datetime = smb_parse_timestamp(tmp_time);
  SMBBUFWRITE(datetime, strlen(datetime));

  /* time changed */
  tmp_time = Curl_read64_le(((unsigned char *)msg + off +
                             sizeof(unsigned int) + 24));
  SMBBUFWRITE("change_time: \t", strlen("change_time: \t"));
  datetime = smb_parse_timestamp(tmp_time);
  SMBBUFWRITE(datetime, strlen(datetime));

  /* handle file attributes */
  SMBBUFWRITE("attributes: \t", strlen("attributes: \t"));

  /* get the attribute flags to compare */
  attributeFlags = Curl_read32_le(((unsigned char *)msg + off +
                            sizeof(unsigned int) + 32));
  if(attributeFlags & attributeCmp[0]) { /* Read-Only */
    SMBBUFWRITE("R", strlen("R"));
  }
  if(attributeFlags & attributeCmp[1]) { /* Hidden */
    SMBBUFWRITE("H", strlen("H"));
  }
  if(attributeFlags & attributeCmp[2]) { /* System */
    SMBBUFWRITE("S", strlen("S"));
  }
  if(attributeFlags & attributeCmp[3]) { /* Directory */
    SMBBUFWRITE("D", strlen("D"));
  }
  if(attributeFlags & attributeCmp[4]) { /* Archive */
    SMBBUFWRITE("A", strlen("A"));
  }
  if(attributeFlags & attributeCmp[5]) { /* Normal */
    SMBBUFWRITE("N", strlen("N"));
  }
  SMBBUFWRITE("\n", strlen("\n"));

  if(len > 0) {
    if(off + sizeof(unsigned int) + len > smbc->got) {
      failf(conn->data, "Invalid input packet");
      *result = CURLE_RECV_ERROR;
    }
    else {
      *result = Curl_client_write(conn, CLIENTWRITE_BODY, smbc->write_buf,
                                  buf_len);
    }
    if(*result) {
      req->result = *result;
      return SMB_TREE_DISCONNECT;
    }
  }
  return SMB_TREE_DISCONNECT;
}

static enum smb_req_state smb_resp_find(struct connectdata *conn,
                                        struct smb_conn *smbc,
                                        struct smb_request *req,
                                        void *msg, CURLcode *result) {
  unsigned short len, data_off, param_off;
  char *buf;
  char *datetime;
  unsigned long list_off = 0;
  size_t utf8_filelen, total_len;
  unsigned char fsize_string[MAX_BUFFER_LEN_64 + 1] = { 0 };
  unsigned char utf16_filename[MAX_LONGNAME_SIZE];
  unsigned char utf8_filename[MAX_LONGNAME_SIZE];
  struct smb_directory_info *smb_dir_info;
  size_t buf_len = 0;
  size_t utf16_filelen = 0;
  void *msg_ptr = NULL;

  buf = smbc->write_buf;

  /* get the contents of TotalDataCount word: size of the data field
   * over all parts */
  total_len = Curl_read16_le(((unsigned char *) msg) +
                             sizeof(struct smb_header) + 3);
  /* get the contents of DataCount word: size of the data field */
  len = Curl_read16_le(((unsigned char *) msg) +
                       sizeof(struct smb_header) + 13);
  /* get the contents of DataOffset word: offset of data field from start of
   * header */
  data_off = Curl_read16_le(((unsigned char *) msg) +
                            sizeof(struct smb_header) + 15);

  if(data_off + sizeof(unsigned int) + len > smbc->got) {
    failf(conn->data, "Invalid input packet\n");
    *result = CURLE_RECV_ERROR;
    return SMB_TREE_DISCONNECT;
  }

  if(req->state == SMB_FINDFIRST || req->state == SMB_FINDNEXT) {
    /* get the contents of ParameterOffset word: offset of parameter field from
     * start of header */
    param_off = Curl_read16_le(((unsigned char *) msg) +
                               sizeof(struct smb_header) + 9);

    /* record SID for follow up searches (only in findfirst params) */
    if(req->state == SMB_FINDFIRST) {
      req->sid = Curl_read16_le(((unsigned char *) msg) + param_off + 4);
    }

    /* record EndOfSearch field in response; it's 0 if search can continue,
     * non-zero if not */
    req->end_of_search = Curl_read16_le(((unsigned char *) msg) + param_off +
                                        (req->state == SMB_FINDFIRST ? 8 : 6));
  }

  /* if the data length is less than total data length, we're going to have
   * multiple responses to handle */
  if(len < total_len) {
    /* if this is the first pass, need to malloc the 'more' buffer */
    if(req->state != SMB_MORE_FINDFIRST && req->state != SMB_MORE_FINDNEXT) {
      smbc->more_buf = malloc(total_len + (smbc->got - len));
      if(!smbc->more_buf) {
        *result = CURLE_OUT_OF_MEMORY;
        return SMB_TREE_DISCONNECT;
      }
    }

    /* copy data into 'more' buffer */
    memcpy(smbc->more_buf + smbc->more_size,
           (const char *)msg + data_off + 4, len);
    smbc->more_size += len;

    /* if the data we've gathered is still less than total, still more */
    if(smbc->more_size < total_len) {
      smbc->sequence -= 1;
      if(req->state == SMB_FINDFIRST || req->state == SMB_MORE_FINDFIRST) {
        return SMB_MORE_FINDFIRST;
      }
      else {
        return SMB_MORE_FINDNEXT;
      }
    }
    else {
      /* we have all of combined message now */
      msg_ptr = smbc->more_buf;
      total_len = smbc->more_size;
    }
  }
  else {
    msg_ptr = (unsigned char *)msg + data_off + 4;
  }

  /* loop through given data, extracting the directory info and parsing it */
  while(list_off + 94 < total_len) {
    /* map offset in buffer to struct for directory information */
    smb_dir_info = (void *)((unsigned char *)msg_ptr + list_off);

    /* filename length (FileNameLength) */
    utf16_filelen = (size_t)smb_dir_info->file_name_length;

    if(list_off + 94 + utf16_filelen > total_len) {
      break;
    }

    /* filename (FileName) */
    memcpy(utf16_filename,
           (const char *)msg_ptr + list_off + 94, utf16_filelen);

    /* convert from UTF-16LE to UTF-8 */
    utf8_filelen = smb_utf16le_to_utf8(utf16_filename, utf16_filelen,
                                       utf8_filename);
    if(utf8_filelen == 0) {
      failf(conn->data, "Unable to convert encoding in response");
      *result = CURLE_RECV_ERROR;
      return SMB_CLOSE;
    }
    SMBBUFWRITE((const char *)utf8_filename, utf8_filelen);
    SMBBUFWRITE("\t", strlen("\t"));

    /* attributes (ExtFileAttributes) */
    smb_parse_attributes(smb_dir_info->ext_file_attributes, buf, &buf_len);
    SMBBUFWRITE("\t", strlen("\t"));

    /* file size (EndOfFile) */
    snprintf((char *)fsize_string, MAX_BUFFER_LEN_64,
             "%" CURL_FORMAT_CURL_OFF_T,
             smb_dir_info->end_of_file);
    SMBBUFWRITE((const char *)fsize_string,
                strlen((const char *)fsize_string));
    SMBBUFWRITE("\t", strlen("\t"));

    /* last written (LastWriteTime) */
    datetime = smb_parse_timestamp((uint64_t)smb_dir_info->last_write_time);
    SMBBUFWRITE(datetime, strlen(datetime));

    /* 0 offset = we're at end (break to avoid trailing bytes) */
    if(!smb_dir_info->next_entry_offset) {
      break;
    }
    else { /* get offset for next in list */
      list_off += smb_dir_info->next_entry_offset;
    }
  }

  if(req->state == SMB_MORE_FINDFIRST || req->state == SMB_MORE_FINDNEXT) {
    free(smbc->more_buf);
    smbc->more_size = 0;
  }

  /* write parsed response out to client */
  *result = Curl_client_write(conn, CLIENTWRITE_BODY, smbc->write_buf,
                                buf_len);

  if(req->end_of_search == 0) {
    /* record last file listed, so follow up search knows
     * where to start from */
    memcpy(req->resume_file, utf16_filename, utf16_filelen);
    req->resume_filelen = (int)utf16_filelen;
    return SMB_FINDNEXT;
  }
  else {
    return SMB_TREE_DISCONNECT;
  }
}

static CURLcode smb2_client_write_query_directory(struct connectdata *conn,
                                                  struct smb_conn *smbc)
{
  if(smbc->more_size == 0)
    return CURLE_RECV_ERROR;

  CURLcode result;
  struct smb2_file_directory_info * smb_dir_info;
  size_t offset = 0;

  char *buf;
  size_t buf_len = 0;
  unsigned char *utf16_filename;
  unsigned char utf8_filename[MAX_LONGNAME_SIZE];
  size_t utf16_filelen;
  size_t utf8_filelen;
  unsigned char fsize_string[MAX_BUFFER_LEN_64 + 1] = { 0 };
  char *datetime;

  buf = smbc->write_buf;

  size_t sizeof_file = sizeof(struct smb2_file_directory_info);

  /* loop through given data, extracting the directory info and parsing it */
  while(offset + sizeof_file < smbc->more_size) {
    /* map offset in buffer to struct for directory information */
    smb_dir_info = (void *)(smbc->more_buf + offset);

    /* filename length (FileNameLength) */
    utf16_filelen = (size_t)smb_dir_info->file_name_length;

    if(offset + sizeof_file + utf16_filelen > smbc->more_size) {
      break;
    }

    /* convert filename (FileName) from UTF-16LE to UTF-8 */
    utf16_filename = (unsigned char *)smbc->more_buf + offset + sizeof_file;
    utf8_filelen = smb_utf16le_to_utf8(utf16_filename, utf16_filelen,
                                       utf8_filename);
    if(utf8_filelen == 0) {
      failf(conn->data, "Unable to convert encoding in response");
      Curl_safefree(smbc->more_buf);
      smbc->more_size = 0;
      return CURLE_RECV_ERROR;
    }
    SMBBUFWRITE((const char *)utf8_filename, utf8_filelen);
    SMBBUFWRITE("\t", strlen("\t"));

    /* attributes (ExtFileAttributes) */
    smb_parse_attributes(smb_dir_info->file_attributes, buf, &buf_len);
    SMBBUFWRITE("\t", strlen("\t"));

    /* file size (EndOfFile) */
    snprintf((char *)fsize_string, MAX_BUFFER_LEN_64, "%" PRIu64,
             smb_dir_info->end_of_file);
    SMBBUFWRITE((const char *)fsize_string,
                strlen((const char *)fsize_string));
    SMBBUFWRITE("\t", strlen("\t"));

    /* last written (LastWriteTime) */
    datetime = smb_parse_timestamp((uint64_t)smb_dir_info->last_write_time);
    SMBBUFWRITE(datetime, strlen(datetime));

    /* if NextEntryOffset is 0 there are no more files in this packet,
     * however we could be processing multiple packets, so check for another */
    if(smb_dir_info->next_entry_offset == 0) {
      if(offset + sizeof_file + smb_dir_info->file_name_length
         >= smbc->more_size)
        /* end of this file in this packet is at the end of the more buffer */
        break;
      else /* increment offset beyond this file, i.e. to next packet */
        offset += sizeof_file + smb_dir_info->file_name_length;
    }
    else { /* increment offset to the next file in list in this packet */
      offset += smb_dir_info->next_entry_offset;
    }
  }

  if(smbc->more_buf) {
    Curl_safefree(smbc->more_buf);
    smbc->more_size = 0;
  }

  /* write parsed response out to client */
  result = Curl_client_write(conn, CLIENTWRITE_BODY, smbc->write_buf, buf_len);

  return result;
}

static enum smb_req_state smb_resp_get_dfs_referral(struct connectdata *conn,
                                                    struct smb_conn *smbc,
                                                    void *msg,
                                                    CURLcode *result) {
  unsigned int ref_off;
  unsigned short len, off, no_of_referrals, ref_version;
  unsigned short DFSPathOff, NetAddressOff;
  unsigned char *utf8;
  char *buf;
  size_t referral_len, i, read_len, utf8_length;
  size_t buf_len = 0;

  buf = smbc->write_buf;

  /* response is for a transaction 2 message, with a DFS_REFERRAL_V1 or V2
   * structure at the end (only interested in V2) */
  /* get the length of the response data field (DataCount) */
  len = Curl_read16_le(((unsigned char *) msg) +
                       sizeof(struct smb_header) + 13);
  /* get the offset for the response data field (DataOffset) */
  off = Curl_read16_le(((unsigned char *) msg) +
                       sizeof(struct smb_header) + 15);

  /* get the number of referral structures in the response */
  no_of_referrals = Curl_read16_le(((unsigned char *) msg) + off + 6);

  /* set referral offset to start of first referral */
  ref_off = off + 8;

  for(i = 0; i < no_of_referrals; i++) {
    /* read referral version */
    ref_version = Curl_read16_le(((unsigned char *)msg + ref_off + 4));

    /* read referral length */
    referral_len = Curl_read32_le(((unsigned char *) msg + (ref_off + 2) + 4));

    if(ref_version == 2) {
      /* get the string offsets */
      DFSPathOff = Curl_read16_le(((unsigned char *)msg + (ref_off + 16) + 4));
      NetAddressOff = Curl_read16_le(((unsigned char *)msg
                                      + (ref_off + 20) + 4));

      /* read path from response */
      read_len = smb_get_unicode_length((unsigned char *)msg + ref_off
                                        + DFSPathOff + 4);
      *result = smb_parse_resp_string(msg, ref_off + DFSPathOff, read_len,
                                      &utf8, &utf8_length, conn);
      if(*result) {
        free(utf8);
        return SMB_TREE_DISCONNECT;
      }
      SMBBUFWRITE(utf8, utf8_length);
      SMBBUFWRITE("\t", strlen("\t"));
      free(utf8);

      /* read target from response */
      read_len = smb_get_unicode_length((unsigned char *)msg + ref_off
                                        + NetAddressOff + 4);
      *result = smb_parse_resp_string(msg, ref_off + NetAddressOff, read_len,
                                      &utf8, &utf8_length, conn);
      if(*result) {
        free(utf8);
        return SMB_TREE_DISCONNECT;
      }
      SMBBUFWRITE(utf8, utf8_length);
      SMBBUFWRITE("\n", strlen("\n"));
      free(utf8);
    }
    /* update referral offset to next target */
    ref_off += (unsigned int)referral_len;
  }

  if(off + sizeof(unsigned int) + len > smbc->got) {
    failf(conn->data, "Invalid input packet");
    *result = CURLE_RECV_ERROR;
    return SMB_TREE_DISCONNECT;
  }
  else {
    *result = Curl_client_write(conn, CLIENTWRITE_BODY, smbc->write_buf,
                                buf_len);
  }

  return SMB_TREE_DISCONNECT;
}

static void smb2_resp_get_dfs_referral(struct connectdata *conn,
                                       struct smb_conn *smbc,
                                       struct smb_request *req, void *msg)
{
  struct smb2_ioctl_response *resp;
  resp = msg;

  if(resp->output_offset == 0)
    return;

  CURLcode result;
  struct smb2_resp_get_dfs_referral *referral_resp;
  uint32_t ref_off;
  struct smb2_dfs_referral_entry *entry;
  struct smb2_dfs_referral_v2 *entryV2;
  struct smb2_dfs_referral_v3 *entryV3;
  unsigned short num_of_referrals;
  unsigned short i;
  unsigned short ref_version;
  unsigned short dfs_path_offset, net_addr_offset;

  char *buf = smbc->write_buf;
  size_t buf_len = 0;

  unsigned char *utf8;
  size_t utf8_length;

  referral_resp = msg + sizeof(struct net_bios_header) + resp->output_offset;

  /* set referral offset to start of first referral */
  ref_off = sizeof(struct net_bios_header) + resp->output_offset
            + sizeof(*referral_resp);

  /* referral_resp contains a referral header followed by a variable
   * number of referral entries (we do not support DFS_REFERRAL_V1) */
  num_of_referrals = referral_resp->number_of_referrals;
  for(i = 0; i < num_of_referrals; i++) {
    dfs_path_offset = 0;
    net_addr_offset = 0;

    entry = msg + ref_off;
    /* read referral version */
    ref_version = smb_swap16(entry->version_number);
    if(ref_version == 2) {
      entryV2 = msg + ref_off;
      /* get the string offsets */
      dfs_path_offset = smb_swap16(entryV2->dfs_path_offset);
      net_addr_offset = smb_swap16(entryV2->network_address_offset);
    }
    else if(ref_version == 3 || ref_version == 4) { /* V3 and V4 are equal */
      entryV3 = msg + ref_off;
      /* DFSV3_NAME_LIST_REFERRAL is set for domain or DC referral responses */
      if((entryV3->entry.referral_entry_flags
          & DFSV3_NAME_LIST_REFERRAL) == 0) {
        /* get the string offsets */
        dfs_path_offset = smb_swap16(entryV3->dfs_path_offset);
        net_addr_offset = smb_swap16(entryV3->network_address_offset);
      }
    }

    if(dfs_path_offset != 0 && net_addr_offset != 0) {
      /* read dfs path from response */
      result = smb2_parse_resp_string((unsigned char *) msg + ref_off
                                      + dfs_path_offset, &utf8, &utf8_length);
      if(result) {
        req->result = result;
        return;
      }
      SMBBUFWRITE(utf8, utf8_length);
      SMBBUFWRITE("\t", strlen("\t"));
      free(utf8);

      /* read network address from response */
      result = smb2_parse_resp_string((unsigned char *)msg + ref_off
                                      + net_addr_offset, &utf8, &utf8_length);
      if(result) {
        req->result = result;
        return;
      }
      SMBBUFWRITE(utf8, utf8_length);
      SMBBUFWRITE("\n", strlen("\n"));
      free(utf8);
    }
    /* update referral offset to next target */
    ref_off += entry->size;
  }

  if(buf_len > 0) {
    result = Curl_client_write(conn, CLIENTWRITE_BODY, smbc->write_buf,
                               buf_len);
    if(result)
      req->result = result;
  }
}

static CURLcode smb_handle_error(struct connectdata *conn,
                                 unsigned int status) {
  /* switch statement matches SMB error codes to Curl error codes */
  switch(status) {
    case NT_STATUS_ACCESS_DENIED:
      failf(conn->data, "NT STATUS: ACCESS_DENIED: Requested access to a "
                        "share/resource but it was not granted");
      return CURLE_REMOTE_ACCESS_DENIED;

    case NT_STATUS_DIRECTORY_NOT_EMPTY:
      failf(conn->data, "NT STATUS: DIRECTORY_NOT_EMPTY: Attempted to delete "
                        "a directory that was not empty");
      return CURLE_SEND_ERROR;

    case NT_STATUS_FILE_IS_A_DIR:
      failf(conn->data, "NT STATUS: FILE_IS_A_DIRECTORY: Attempted to perform "
                        "a non-directory command on a directory");
      return CURLE_SEND_ERROR;

    case NT_STATUS_INSUFF_SERVER_RESOURCES:
      failf(conn->data, "NT STATUS: INSUFF_SERVER_RESOURCES: Server does not "
                        "have sufficient resources to complete command");
      return CURLE_REMOTE_DISK_FULL;

    case NT_STATUS_NO_SUCH_FILE:
      failf(conn->data, "NT STATUS: NO_SUCH_FILE: File requested does not "
                        "exist");
      return CURLE_REMOTE_FILE_NOT_FOUND;

    case NT_STATUS_NOT_A_DIRECTORY:
      failf(conn->data, "NT STATUS: NOT_A_DIRECTORY: Attempted to perform a "
                        "directory specific command on an object that is not "
                        "a directory");
      return CURLE_SEND_ERROR;

    case NT_STATUS_OBJECT_NAME_COLLISION:
      failf(conn->data, "NT STATUS: OBJECT_NAME_COLLISION: A file/directory "
                        "already exists with the name given");
      return CURLE_REMOTE_FILE_EXISTS;

    case NT_STATUS_OBJECT_NAME_INVALID:
      failf(conn->data, "NT STATUS: OBJECT_NAME_INVALID: The given name "
                        "contains invalid characters, or is otherwise "
                        "invalid");
      return CURLE_URL_MALFORMAT;

    case NT_STATUS_OBJECT_NAME_NOT_FOUND:
      failf(conn->data, "NT STATUS: OBJECT_NAME_NOT_FOUND: File requested "
                        "does not exist");
      return CURLE_REMOTE_FILE_NOT_FOUND;

    case NT_STATUS_OBJECT_PATH_NOT_FOUND:
      failf(conn->data, "NT STATUS: OBJECT_PATH_NOT_FOUND: Path requested "
                        "does not exist");
      return CURLE_REMOTE_FILE_NOT_FOUND;

    case NT_STATUS_BAD_NETWORK_NAME:
      failf(conn->data, "NT STATUS: BAD_NETWORK_NAME: Specified share name "
                        "cannot be found on remote server");
      return CURLE_REMOTE_FILE_NOT_FOUND;

    case NT_STATUS_NOT_FOUND:
      failf(conn->data, "NT STATUS: NOT_FOUND: Object not found - if you "
                        "asked for DFS referral, there is none");
      return CURLE_REMOTE_FILE_NOT_FOUND;

    case NT_STATUS_PATH_NOT_COVERED:
      failf(conn->data, "NT STATUS: PATH_NOT_COVERED: Contacted server does "
                        "not support the indicated part of the DFS namespace");
      return CURLE_REMOTE_FILE_NOT_FOUND;

    case NT_STATUS_INVALID_PARAMETER:
      failf(conn->data, "NT STATUS: INVALID_PARAMETER: The parameter "
                        "is incorrect");
      return CURLE_URL_MALFORMAT;

    default:
      failf(conn->data, "An error occurred in the SMB response");
      return CURLE_SEND_ERROR;
  }
}

static void smb_passwd_hash(struct connectdata *conn, struct smb_conn *smbc)
{
  unsigned char lm_hash[21];
  unsigned char lm[24];
  unsigned char nt_hash[21];
  unsigned char nt[24];
  unsigned char ntlm_hash[16];
  unsigned char session_key[16];
  unsigned char MAC_key[40];
#ifdef USE_OPENSSL
  MD4_CTX MD4pw;
#elif defined(USE_GNUTLS_NETTLE)
  struct md4_ctx MD4pw;
#elif defined(USE_GNUTLS)
  gcry_md_hd_t MD4pw;
#elif defined(USE_WIN32_CRYPTO)
  HCRYPTPROV hprov;
  HCRYPTHASH hhash;
  DWORD length = 16;
#endif

  /* create the hashes & responses */
  Curl_ntlm_core_mk_lm_hash(conn->data, conn->passwd, lm_hash);
  Curl_ntlm_core_lm_resp(lm_hash, smbc->challenge, lm);
  memcpy(smbc->lm_resp, lm, sizeof(lm));
#ifdef USE_NTRESPONSES
  Curl_ntlm_core_mk_nt_hash(conn->data, conn->passwd, nt_hash);
  Curl_ntlm_core_lm_resp(nt_hash, smbc->challenge, nt);
  memcpy(smbc->nt_resp, nt, sizeof(nt));
  if(smbc->sig_required) {

    /* generate the NTLM session key for signing */
    memset(session_key, 0, 16);
    memcpy(ntlm_hash, nt_hash, sizeof(ntlm_hash));

#ifdef USE_OPENSSL
    MD4_Init(&MD4pw);
    MD4_Update(&MD4pw, ntlm_hash, sizeof(ntlm_hash));
    MD4_Final(session_key, &MD4pw);
#elif defined(USE_GNUTLS_NETTLE)
    md4_init(&MD4pw);
    md4_update(&MD4pw, (unsigned int)(sizeof(ntlm_hash)), ntlm_hash);
    md4_digest(&MD4pw, MD4_DIGEST_SIZE, session_key);
#elif defined(USE_GNUTLS)
    gcry_md_open(&MD4pw, GCRY_MD_MD4, 0);
    gcry_md_write(MD4pw, ntlm_hash, sizeof(ntlm_hash));
    memcpy(session_key, gcry_md_read(MD4pw, 0), MD4_DIGEST_LENGTH);
    gcry_md_close(MD4pw);
#elif defined(USE_NSS) || defined(USE_OS400CRYPTO)
    Curl_md4it(session_key, ntlm_hash, sizeof(ntlm_hash));
#elif defined(USE_DARWINSSL)
    (void)CC_MD4(ntlm_hash, (CC_LONG)(sizeof(ntlm_hash)), session_key);
#elif defined(USE_WIN32_CRYPTO)
    if(CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT)) {
      if(CryptCreateHash(hprov, CALG_MD4, 0, 0, &hhash)) {
        CryptHashData(hhash, ntlm_hash, (unsigned int)sizeof(ntlm_hash), 0);
        CryptGetHashParam(hhash, HP_HASHVAL, session_key, &length, 0);
        CryptDestroyHash(hhash);
      }
      CryptReleaseContext(hprov, 0);
    }
#endif

    /* create MAC key */
    memcpy(MAC_key, session_key, 16);
    memcpy(MAC_key + 16, smbc->nt_resp, 24);
    memcpy(smbc->MAC_key, MAC_key, sizeof(smbc->MAC_key));

    /* init sequence to 0 */
    smbc->sequence = 0;
  }
#else
    memset(smbc->nt_resp, 0, sizeof(smbc->nt_resp));
    if(smbc->sec_sig_req) {

      /* generate the LM session key for signing */
      memset(session_key, 0, 16);
      memcpy(session_key, lm_hash, 8);
      memcpy(session_key + 8, "\0\0\0\0\0\0\0\0", 8);

      /* create MAC key */
      memcpy(MAC_key, session_key, 16);
      memcpy(MAC_key + 16, smbc->lm_resp, 24);
      memcpy(smbc->MAC_key, MAC_key, sizeof(smbc->MAC_key));

      /* init sequence to 0 */
      smbc->sequence = 0;
    }
#endif
}

static CURLcode smb2_resp_file_info(struct connectdata *conn,
                                    struct smb_conn *smbc,
                                    struct smb_request *req, void *msg)
{
  struct smb2_header *h;
  size_t offset = sizeof(struct net_bios_header);
  h = msg + offset;
  if(h->next_command) {
    offset += h->next_command;
    struct smb2_close_response *close_response = msg + offset;

    char *buf = smbc->write_buf;
    size_t buf_len = 0;

    unsigned char fsize_string[MAX_BUFFER_LEN_64 + 1] = {0};
    uint64_t filesize;

    char *datetime;
    uint64_t tmp_time = 0;

    /* file name */
    SMBBUFWRITE("filename: \t", strlen("filename: \t"));
    if(strlen(req->path) == 0) {
      SMBBUFWRITE("/", 1);
    }
    else {
      SMBBUFWRITE(req->path, strlen(req->path));
    }
    SMBBUFWRITE("\n", strlen("\n"));

    /* file size (EndOfFile) */
    filesize = smb_swap64(close_response->end_of_file);
    snprintf((char *) fsize_string, MAX_BUFFER_LEN_64, "%" PRIu64, filesize);
    SMBBUFWRITE("file_size: \t", strlen("file_size: \t"));
    SMBBUFWRITE((const char *) fsize_string,
                strlen((const char *) fsize_string));
    SMBBUFWRITE("\n", strlen("\n"));

    /* time created */
    tmp_time = smb_swap64(close_response->creation_time);
    SMBBUFWRITE("create_time: \t", strlen("create_time: \t"));
    datetime = smb_parse_timestamp(tmp_time);
    SMBBUFWRITE(datetime, strlen(datetime));

    /* last accessed */
    tmp_time = smb_swap64(close_response->last_access_time);
    SMBBUFWRITE("access_time: \t", strlen("access_time: \t"));
    datetime = smb_parse_timestamp(tmp_time);
    SMBBUFWRITE(datetime, strlen(datetime));

    /* last written */
    tmp_time = smb_swap64(close_response->last_write_time);
    SMBBUFWRITE("write_time: \t", strlen("write_time: \t"));
    datetime = smb_parse_timestamp(tmp_time);
    SMBBUFWRITE(datetime, strlen(datetime));

    /* time changed */
    tmp_time = smb_swap64(close_response->change_time);
    SMBBUFWRITE("change_time: \t", strlen("change_time: \t"));
    datetime = smb_parse_timestamp(tmp_time);
    SMBBUFWRITE(datetime, strlen(datetime));

    /* attributes */
    SMBBUFWRITE("attributes: \t", strlen("attributes: \t"));
    smb_parse_attributes(close_response->file_attributes, buf, &buf_len);
    SMBBUFWRITE("\n", strlen("\n"));

    if(buf_len > 0)
      return Curl_client_write(conn, CLIENTWRITE_BODY, smbc->write_buf,
                               buf_len);
  }
  return CURLE_OK;
}

static CURLcode smb_connection_state(struct connectdata *conn, bool *done)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  struct smb_negotiate_response *nrsp;
  struct smb2_negotiate_response *smb2_negotiate_resp;
  struct smb2_session_setup_response *smb2_session_setup_resp;
  struct smb_header *h;
  struct smb2_header *h2;
  CURLcode result;
  void *msg = NULL;

  if(smbc->state == SMB_CONNECTING) {
#ifdef USE_SSL
    if((conn->handler->flags & PROTOPT_SSL)) {
      bool ssl_done = FALSE;
      result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &ssl_done);
      if(result && result != CURLE_AGAIN)
        return result;
      if(!ssl_done)
        return CURLE_OK;
    }
#endif

    result = smb_send_negotiate(conn);
    if(result) {
      connclose(conn, "SMB: failed to send negotiate message");
      return result;
    }

    conn_state(conn, SMB_NEGOTIATE);
  }

  /* Send the previous message and check for a response */
  result = smb_send_and_recv(conn, &msg);
  if(result && result != CURLE_AGAIN) {
    connclose(conn, "SMB: failed to communicate");
    return result;
  }

  if(!msg)
    return CURLE_OK;

  h2 = msg + sizeof(struct net_bios_header);
  if(h2->protocol_id[0] == 0xfe) {
    /* This server wants to use SMBv2 */
    /* TODO might need to track: smbc->credits_granted += h2->credit_rx; */
    switch(smbc->state) {
      case SMB_NEGOTIATE:
      case SMB2_NEGOTIATE:
        if(h2->status) {
          connclose(conn, "SMBv2: negotiation failed");
          return CURLE_COULDNT_CONNECT;
        }
        smb2_negotiate_resp = msg;
        smbc->smb_version = smb2_negotiate_resp->dialect_revision;
        if(smb2_negotiate_resp->dialect_revision == SMB2FF_DIALECT) {
         /* Server supports SMBv2.1 and above,
           need to negotiate the version to use */
          result = smb2_send_negotiate(conn);
          if(result) {
            connclose(conn, "SMBv2: failed to send negotiate message");
            return result;
          }
          conn_state(conn, SMB2_NEGOTIATE);
          break;
        }

        smbc->dialect_revision = smb2_negotiate_resp->dialect_revision;
        if(is_smb_v2(smbc)) {
          memcpy(&smbc->server_guid, smb2_negotiate_resp->server_guid, 16);

          smbc->max_transact_size =
            smb_swap32(smb2_negotiate_resp->max_transact_size);
          smbc->max_read_size =
            smb_swap32(smb2_negotiate_resp->max_read_size);
          smbc->max_write_size =
            smb_swap32(smb2_negotiate_resp->max_write_size);

          uint32_t capabilites = smb_swap32(smb2_negotiate_resp->capabilities);
          if(capabilites & SMB2_GLOBAL_CAP_DFS) {
            smbc->using_dfs = true;
          }
          else {
            smbc->using_dfs = false;
          }

          if(smbc->dialect_revision >= SMB210_DIALECT
             && capabilites & SMB2_GLOBAL_CAP_LARGE_MTU) {
            smbc->multi_credit = true;
          }
          else {
            smbc->multi_credit = false;
          }

          #ifdef USE_OPENSSL
          if(smb_swap16(smb2_negotiate_resp->security_mode) > 0) {
            if(smbc->dialect_revision >= SMB300_DIALECT) {
              #ifndef OPENSSL_NO_CMAC
                smbc->sig_required = true;
              #endif
            }
            else
              smbc->sig_required = true;
          }
          #endif

          /* If the underlying transport is NETBIOS over TCP,
          * Windows-based servers set MaxTransactSize to 65536
     * https://msdn.microsoft.com/en-us/library/cc246805.aspx#Appendix_A_232 */
          if(smbc->max_transact_size > MAX_NET_BIOS_PAYLOAD_SIZE)
            smbc->max_transact_size = MAX_NET_BIOS_PAYLOAD_SIZE;
          if(smbc->max_read_size > MAX_NET_BIOS_PAYLOAD_SIZE)
            smbc->max_read_size = MAX_NET_BIOS_PAYLOAD_SIZE;
          /* TODO maybe should not have this limit, but used by uploadbuffer */
          if(smbc->max_write_size > CURL_MAX_WRITE_SIZE)
            smbc->max_write_size = CURL_MAX_WRITE_SIZE;
          /* if max transact size from negotiate response is more than max
           * message size, then reallocate the recv buffer to this new size */
          if(smbc->max_transact_size > MAX_MESSAGE_SIZE) {
            char *tmp_buf = realloc(smbc->recv_buf, smbc->max_transact_size);
            if(!tmp_buf) {
              Curl_safefree(smbc->recv_buf);
              return CURLE_OUT_OF_MEMORY;
            }
            smbc->recv_buf = tmp_buf;
          }

          result = smb2_send_session_setup_type1(conn);
          if(result) {
            connclose(conn, "SMBv2: failed to send negotiate message");
            return result;
          }
          conn_state(conn, SMB2_SESSION_SETUP);
        }
        else {
          connclose(conn, "SMBv2: negotiation failed, unsupported dialect");
          return CURLE_COULDNT_CONNECT;
        }
        break;

      case SMB2_SESSION_SETUP:
        if(h2->status == STATUS_MORE_PROCESSING_REQUIRED) {
          smb2_session_setup_resp = msg;

          if(smb2_session_setup_resp->message_type == 0x00000002) {
            char *identifier = NULL;
            size_t byte_count = 0;
            Curl_base64_encode(NULL,
                               (const char *)
                                 &smb2_session_setup_resp->identifier,
                               smb2_session_setup_resp->security_buffer_length,
                               &identifier, &byte_count);
            Curl_auth_decode_ntlm_type2_message(conn->data,
                                                (const char *)
                                                  identifier, &conn->ntlm);
            if(identifier)
              free(identifier);
            smbc->session_id = smb2_session_setup_resp->h2.session_id;

            result = smb2_send_session_setup_type3(conn);
            if(result) {
              connclose(conn, "SMBv2: failed to send session setup message");
              return result;
            }
            conn_state(conn, SMB2_SESSION_SETUP_SENT);
          }
        }
        else {
          connclose(conn, "SMBv2: session setup failed");
          return CURLE_COULDNT_CONNECT;
        }
        break;

      case SMB2_SESSION_SETUP_SENT:
        if(h2->status) {
          connclose(conn, "SMBv2: authentication failed");
          return CURLE_LOGIN_DENIED;
        }
        conn_state(conn, SMB_CONNECTED);
        *done = true;
        break;

      default:
        smb_pop_message(conn);
        return CURLE_OK; /* ignore */
    }
  }
  else {
    h = msg;

    switch(smbc->state) {
      case SMB_NEGOTIATE:
        if(h->status) {
          connclose(conn, "SMB: negotiation failed");
          return CURLE_COULDNT_CONNECT;
        }
        nrsp = msg;
        memcpy(smbc->challenge, nrsp->bytes, sizeof(smbc->challenge));
        smbc->session_key = smb_swap32(nrsp->session_key);

        /* Check security mode for message signing required */
        if(nrsp->security_mode & 0x08)
          smbc->sig_required = true;
        else
          smbc->sig_required = false;

        smb_passwd_hash(conn, smbc);

        result = smb_send_setup(conn);
        if(result) {
          connclose(conn, "SMB: failed to send setup message");
          return result;
        }
        conn_state(conn, SMB_SETUP);
        break;

      case SMB_SETUP:
        if(h->status) {
          connclose(conn, "SMB: authentication failed");
          return CURLE_LOGIN_DENIED;
        }
        smbc->uid = smb_swap16(h->uid);
        conn_state(conn, SMB_CONNECTED);
        *done = true;
        break;

      default:
        smb_pop_message(conn);
        return CURLE_OK; /* ignore */
    }
  }
  smb_pop_message(conn);

  return CURLE_OK;
}

/* Recursive function for checking compound SMBv2 responses for errors*/
static void check_compound_message_for_errors(struct connectdata *conn,
                                              struct smb2_header *h,
                                              struct smb_request *req,
                                              void *msg, size_t offset)
{
  if(h->status) {
    req->result =  smb_handle_error(conn, h->status);
  }
  else if(h->next_command) {
    offset += h->next_command;
    h = msg + offset;
    check_compound_message_for_errors(conn, h, req, msg, offset);
  }
}

static CURLcode smb2_request_state(struct connectdata *conn, bool *done)
{
  struct smb_request *req = conn->data->req.protop;
  struct smb2_header *h;
  struct smb_conn *smbc = &conn->proto.smbc;
  enum smb_req_state next_state = SMB_DONE;
  CURLcode result;
  void *msg = NULL;

  /* Start the request */
  if(req->state == SMB_REQUESTING) {
    result = smb2_send_tree_connect(conn);
    if(result) {
      connclose(conn, "SMBv2: failed to send tree connect message");
      return result;
    }

    request_state(conn, SMB_TREE_CONNECT);
  }

  /* Send the previous message and check for a response */
  result = smb_send_and_recv(conn, &msg);
  if(result && result != CURLE_AGAIN) {
    connclose(conn, "SMBv2: failed to communicate");
    return result;
  }

  if(!msg)
    return CURLE_OK;

  h = msg + sizeof(struct net_bios_header);
  /* TODO might need to track: smbc->credits_granted += h->credit_rx; */

  switch(req->state) {
    case SMB_TREE_CONNECT:
      if(h->status) {
        req->result = smb_handle_error(conn, h->status);
        next_state = SMB2_LOGOFF;
        break;
      }
      smbc->tree_id = smb_swap32(h->tree_id);
      next_state = smb_resp_tree_connect(req);
      if(next_state == SMB_FILE_SHORTNAME)
        next_state = SMB_FILE_ALLINFO;
      break;

    case SMB_CHECKDFS:
      if(h->status) {
        req->result = smb_handle_error(conn, h->status);
      }
      else {
        smb2_resp_get_dfs_referral(conn, smbc, req, msg);
      }
      next_state = SMB_TREE_DISCONNECT;
      break;

    case SMB_OPEN:
      if(h->status) {
        req->result = smb_handle_error(conn, h->status);
        next_state = SMB_TREE_DISCONNECT;
        break;
      }
      next_state = smb2_handle_create_open_resp(conn, msg);
      smb2_handle_create_resp(smbc, msg);
      break;

    case SMB_DOWNLOAD:
      if(h->status && h->status != NT_STATUS_END_OF_FILE) {
        req->result = smb_handle_error(conn, h->status);
        next_state = SMB_CLOSE;
        break;
      }
      next_state = smb2_handle_read_resp(conn, smbc, req, msg);
      break;

    case SMB_UPLOAD:
      if(h->status) {
        req->result = smb_handle_error(conn, h->status);
        next_state = SMB_CLOSE;
        break;
      }
      next_state = smb2_handle_write_resp(conn, smbc, req, msg);
      break;

    case SMB_CLOSE:
      next_state = SMB_TREE_DISCONNECT;
      break;

    case SMB_TREE_DISCONNECT:
      conn->proto.smbc.tree_id = 0;
      next_state = SMB2_LOGOFF;
      break;

    case SMB2_LOGOFF:
      next_state = SMB_DONE;
      break;

    case SMB_DELETE:
    case SMB_DELDIR:
    case SMB_RENAME:
    case SMB_MOVE:
    case SMB_MKDIR:
      check_compound_message_for_errors(conn, h, req, msg,
                                        sizeof(struct net_bios_header));
      next_state = SMB_TREE_DISCONNECT;
      break;

    case SMB_FINDFIRST:
      if(h->status) {
        req->result = smb_handle_error(conn, h->status);
        next_state = SMB_CLOSE;
        break;
      }
      smb2_handle_create_resp(smbc, msg);
      next_state = SMB_FINDNEXT;
      break;

    case SMB_FINDNEXT:
      if(h->status == NT_STATUS_NO_MORE_FILES) {
        next_state = SMB_CLOSE;
        break;
      }
      else if(h->status) {
        req->result = smb_handle_error(conn, h->status);
        next_state = SMB_CLOSE;
        break;
      }
      req->result = smb2_resp_query_directory(smbc, msg);
      if(!req->result)
        req->result = smb2_client_write_query_directory(conn, smbc);
      if(!req->result)
        next_state = SMB_FINDNEXT;
      else
        next_state = SMB_CLOSE;
      break;

    case SMB_FILE_ALLINFO:
    case SMB2_DIR_ALLINFO:
      check_compound_message_for_errors(conn, h, req, msg,
                                        sizeof(struct net_bios_header));
      if(!req->result)
        req->result = smb2_resp_file_info(conn, smbc, req, msg);
      if(req->result == CURLE_SEND_ERROR
         && h->status == NT_STATUS_FILE_IS_A_DIR) {
        req->result = CURLE_OK; /* clear the error */
        next_state = SMB2_DIR_ALLINFO; /* try again this time as a directory */
      }
      else
        next_state = SMB_TREE_DISCONNECT;
      break;

    default:
      smb_pop_message(conn);
      return CURLE_OK; /* ignore */
  }

  smb_pop_message(conn);

  switch(next_state) {
    case SMB_CHECKDFS:
      result = smb2_send_get_dfs_referral(conn);
      break;

    case SMB_DONE:
      result = req->result;
      *done = true;
      break;

    case SMB_CLOSE:
      result = smb2_send_close(conn);
      break;

    case SMB_TREE_DISCONNECT:
      result = smb2_send_tree_disconnect(conn);
      break;

    case SMB2_LOGOFF:
      result = smb2_send_logoff(conn);
      break;

    case SMB_DOWNLOAD:
      result = smb2_send_read(conn);
      break;

    case SMB_UPLOAD:
      result = smb2_send_write(conn);
      break;

    case SMB_DELETE:
    case SMB_DELDIR:
      result = smb2_send_delete(conn);
      break;

    case SMB_RENAME:
      result = smb2_send_rename(conn);
      break;

    case SMB_MOVE:
      result = smb2_send_move(conn);
      break;

    case SMB_MKDIR:
      result = smb2_send_mkdir(conn);
      break;

    case SMB_FINDNEXT:
      result = smb2_send_query_directory(conn);
      break;

    case SMB_FILE_ALLINFO:
    case SMB2_DIR_ALLINFO:
      result = smb2_send_file_info(conn, next_state);
      break;

    case SMB_FINDFIRST:
    case SMB_OPEN:
      /* LIST/DOWNLOAD/UPLOAD */
      result = smb2_send_create(conn, next_state);
      break;

    default:
      result = CURLE_SEND_ERROR;
      break;
  }

  if(result) {
    connclose(conn, "SMBv2: failed to send message");
    Curl_safefree(smbc->write_buf);
    return result;
  }

  request_state(conn, next_state);

  return CURLE_OK;
}

static CURLcode smb_request_state(struct connectdata *conn, bool *done)
{
  struct smb_conn * smbc = &conn->proto.smbc;
  if(is_smb_v2(smbc))
    return smb2_request_state(conn, done);

  struct smb_request *req = conn->data->req.protop;
  struct smb_header *h;
  enum smb_req_state next_state = SMB_DONE;
  CURLcode result;
  void *msg = NULL;

  /* Start the request */
  if(req->state == SMB_REQUESTING) {
    result = smb_send_tree_connect(conn);
    if(result) {
      connclose(conn, "SMB: failed to send tree connect message");
      return result;
    }

    request_state(conn, SMB_TREE_CONNECT);
  }

  /* Send the previous message and check for a response */
  result = smb_send_and_recv(conn, &msg);
  if(result && result != CURLE_AGAIN) {
    connclose(conn, "SMB: failed to communicate");
    return result;
  }

  if(!msg)
    return CURLE_OK;

  h = msg;

  switch(req->state) {
  case SMB_TREE_CONNECT:
    if(h->status) {
      req->result = smb_handle_error(conn, h->status);
      break;
    }
    req->tid = smb_swap16(h->tid);
    next_state = smb_resp_tree_connect(req);
    break;

  case SMB_CHECKDFS:
    if(h->status) {
      req->result = smb_handle_error(conn, h->status);
      break;
    }
    next_state = smb_resp_get_dfs_referral(conn, smbc, msg, &result);
    break;

  case SMB_OPEN:
    if(h->status) {
      req->result = smb_handle_error(conn, h->status);
      next_state = SMB_TREE_DISCONNECT;
      break;
    }
    req->fid = smb_swap16(((struct smb_nt_create_response *)msg)->fid);
    next_state = smb_resp_open(conn, req, msg);
    break;

  case SMB_DOWNLOAD:
    if(h->status) {
      req->result = smb_handle_error(conn, h->status);
      next_state = SMB_CLOSE;
      break;
    }
    next_state = smb_resp_download(conn, smbc, req, msg, &result);
    break;

  case SMB_UPLOAD:
    if(h->status) {
      req->result = smb_handle_error(conn, h->status);
      next_state = SMB_CLOSE;
      break;
    }
    next_state = smb_resp_upload(conn, msg);
    break;

  case SMB_FILE_SHORTNAME:
    if(h->status) {
      req->result = smb_handle_error(conn, h->status);
      next_state = SMB_CLOSE;
      break;
    }
    next_state = smb_resp_file_shortname(conn, smbc, req, msg, &result);
    break;

  case SMB_FILE_ALLINFO:
    if(h->status) {
      req->result = smb_handle_error(conn, h->status);
      next_state = SMB_CLOSE;
      break;
    }
    next_state = smb_resp_file_allinfo(conn, smbc, req, msg, &result);
    break;

  case SMB_FINDFIRST:
  case SMB_FINDNEXT:
  case SMB_MORE_FINDFIRST:
  case SMB_MORE_FINDNEXT:
    if(h->status) {
      req->result = smb_handle_error(conn, h->status);
      next_state = SMB_CLOSE;
      break;
    }
    next_state = smb_resp_find(conn, smbc, req, msg, &result);
    break;

  case SMB_MOVE:
  case SMB_MKDIR:
  case SMB_DELDIR:
  case SMB_DELETE:
  case SMB_RENAME:
    if(h->status) {
      req->result = smb_handle_error(conn, h->status);
      next_state = SMB_TREE_DISCONNECT;
      break;
    }
    next_state = SMB_TREE_DISCONNECT;
    break;

  case SMB_CLOSE:
    /* We don't care if the close failed, proceed to tree disconnect anyway */
    next_state = SMB_TREE_DISCONNECT;
    break;

  case SMB_TREE_DISCONNECT:
    next_state = SMB_DONE;
    break;

  default:
    smb_pop_message(conn);
    return CURLE_OK; /* ignore */
    case SMB_REQUESTING:break;
    case SMB_DONE:break;
  }

  smb_pop_message(conn);

  switch(next_state) {
  case SMB_CHECKDFS:
    result = smb_send_get_dfs_referral(conn);
    break;

  case SMB_OPEN:
    result = smb_send_open(conn);
    break;

  case SMB_DOWNLOAD:
    result = smb_send_read(conn);
    break;

  case SMB_UPLOAD:
    result = smb_send_write(conn);
    break;

  case SMB_RENAME:
    result = smb_send_rename(conn);
    break;

  case SMB_DELETE:
    result = smb_send_delete(conn);
    break;

  case SMB_MKDIR:
    result = smb_send_mkdir(conn);
    break;

  case SMB_DELDIR:
    result = smb_send_deldir(conn);
    break;

  case SMB_MOVE:
    result = smb_send_move(conn);
    break;

  case SMB_FILE_SHORTNAME:
    result = smb_send_file_name(conn);
    break;

  case SMB_FILE_ALLINFO:
    result = smb_send_file_info(conn);
    break;

  case SMB_FINDFIRST:
    result = smb_send_find_first_ls(conn);
    break;

  case SMB_FINDNEXT:
    result = smb_send_find_next_ls(conn);
    break;

  case SMB_CLOSE:
    result = smb_send_close(conn);
    break;

  case SMB_TREE_DISCONNECT:
    result = smb_send_tree_disconnect(conn);
    break;

  case SMB_MORE_FINDFIRST:
  case SMB_MORE_FINDNEXT:
    result = CURLE_OK;
    break;

  case SMB_DONE:
    result = req->result;
    *done = true;
    break;

  default:
    result = CURLE_SEND_ERROR;
    break;
  }

  if(result) {
    connclose(conn, "SMB: failed to send message");
    Curl_safefree(smbc->write_buf);
    return result;
  }

  request_state(conn, next_state);

  return CURLE_OK;
}

static CURLcode smb_done(struct connectdata *conn, CURLcode status,
                         bool premature)
{
  struct smb_request *req = conn->data->req.protop;
  (void) premature;
  Curl_safefree(req->custom);
  Curl_safefree(conn->data->req.protop);
  return status;
}

static CURLcode smb_disconnect(struct connectdata *conn, bool dead)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  struct smb_request *req = conn->data->req.protop;
  (void) dead;
  Curl_safefree(smbc->share);
  Curl_safefree(smbc->domain);
  Curl_safefree(smbc->recv_buf);
  Curl_safefree(smbc->write_buf);
  if (req) {
    Curl_safefree(req->custom);
  }

  return CURLE_OK;
}

static int smb_getsock(struct connectdata *conn, curl_socket_t *socks,
                       int numsocks)
{
  if(!numsocks)
    return GETSOCK_BLANK;

  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_READSOCK(0) | GETSOCK_WRITESOCK(0);
}

static CURLcode smb_do(struct connectdata *conn, bool *done)
{
  struct smb_conn *smbc = &conn->proto.smbc;
  struct smb_request *req = conn->data->req.protop;

  *done = FALSE;
  if(smbc->share) {
    req->path = strchr(smbc->share, '\0');
    if(req->path) {
      req->path++;
      return CURLE_OK;
    }
  }
  return CURLE_URL_MALFORMAT;
}

static CURLcode smb_parse_url_path(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct smb_conn *smbc = &conn->proto.smbc;
  char *path;
  char *slash;

  /* URL decode the path */
  result = Curl_urldecode(data, data->state.path, 0, &path, NULL, TRUE);
  if(result)
    return result;

  /* Parse the path for the share */
  smbc->share = strdup((*path == '/' || *path == '\\') ? path + 1 : path);
  free(path);
  if(!smbc->share)
    return CURLE_OUT_OF_MEMORY;

  slash = strchr(smbc->share, '/');
  if(!slash)
    slash = strchr(smbc->share, '\\');

  /* The share must be present */
  if(!slash) {
    Curl_safefree(smbc->share);
    return CURLE_URL_MALFORMAT;
  }

  /* Parse the path for the file path converting any forward slashes into
     backslashes */
  *slash++ = 0;

  for(; *slash; slash++) {
    if(*slash == '/')
      *slash = '\\';
  }
  return CURLE_OK;
}

/***********************************************************************
 *
 * smb_parse_custom_request()
 *
 * Parse the custom request.
 */
static CURLcode smb_parse_custom_request(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct smb_request *req = data->req.protop;
  char *custom;
  char *params;

  if(data->set.str[STRING_CUSTOMREQUEST]) {
    /* URL decode the custom request */
    result = Curl_urldecode(data, data->set.str[STRING_CUSTOMREQUEST], 0,
                            &custom, NULL, TRUE);
    req->custom = strdup(custom);
    if(!req->custom) {
      return CURLE_OUT_OF_MEMORY;
    }
    free(custom);

    /* Extract the parameters if specified */
    if(!result) {
      params = strchr(req->custom, ' ');

      if(params) {
        *params++ = 0;
        req->custom_params = params;
      }
    }
  }

  return result;
}

#endif /* !USE_WINDOWS_SSPI || USE_WIN32_CRYPTO */

#endif /* CURL_DISABLE_SMB && USE_NTLM && CURL_SIZEOF_CURL_OFF_T > 4 */
