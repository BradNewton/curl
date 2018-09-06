#ifndef HEADER_CURL_SMB_H
#define HEADER_CURL_SMB_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014, Bill Nagel <wnagel@tycoint.com>, Exacq Technologies
 * Copyright (C) 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
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

enum smb_conn_state {
  SMB_NOT_CONNECTED = 0,
  SMB_CONNECTING,
  SMB_NEGOTIATE,
  SMB_SETUP,
  SMB_CONNECTED,
  SMB2_NEGOTIATE,
  SMB2_SESSION_SETUP,
  SMB2_SESSION_SETUP_SENT
};

struct smb_conn {
  enum smb_conn_state state;
  char *user;
  char *domain;
  char *share;
  unsigned char challenge[8];
  unsigned char lm_resp[24];
  unsigned char nt_resp[24];
  unsigned char MAC_key[40];
  unsigned int session_key;
  unsigned short uid;
  char *recv_buf;
  char *write_buf;
  char *more_buf;
  size_t more_size;
  size_t upload_size;
  size_t send_size;
  size_t sent;
  size_t got;
  bool sig_required;
  int sequence;
  unsigned short smb_version;
  /* SMB v2 values */
  unsigned short dialect_revision;
  uint64_t message_id;
  unsigned char server_guid[16];
  uint32_t max_transact_size;
  uint32_t max_read_size;
  uint32_t max_write_size;
  bool using_dfs;
  bool multi_credit;
  uint64_t session_id;
  uint32_t tree_id;
  unsigned char random_session_key[16];
  unsigned char exported_session_key[16];
  unsigned char file_id[16];
  uint32_t expected_write;
};

/*
 * Definitions for SMB protocol data structures
 */
#ifdef BUILDING_CURL_SMB_C

#include "smb2.h"

#if defined(_MSC_VER) || defined(__ILEC400__)
#  define PACK
#  pragma pack(push)
#  pragma pack(1)
#elif defined(__GNUC__)
#  define PACK __attribute__((packed))
#else
#  define PACK
#endif

#define SMB_COM_CREATE_DIRECTORY          0x00
#define SMB_COM_DELETE_DIRECTORY          0x01
#define SMB_COM_CLOSE                     0x04
#define SMB_COM_DELETE                    0x06
#define SMB_COM_RENAME                    0x07
#define SMB_COM_READ_ANDX                 0x2e
#define SMB_COM_WRITE_ANDX                0x2f
#define SMB_COM_TRANSACTION2              0x32
#define SMB_COM_TREE_DISCONNECT           0x71
#define SMB_COM_NEGOTIATE                 0x72
#define SMB_COM_SETUP_ANDX                0x73
#define SMB_COM_TREE_CONNECT_ANDX         0x75
#define SMB_COM_NT_CREATE_ANDX            0xa2
#define SMB_COM_NO_ANDX_COMMAND           0xff

#define SMB_WC_CLOSE                      0x03
#define SMB_WC_READ_ANDX                  0x0c
#define SMB_WC_WRITE_ANDX                 0x0e
#define SMB_WC_SETUP_ANDX                 0x0d
#define SMB_WC_TREE_CONNECT_ANDX          0x04
#define SMB_WC_NT_CREATE_ANDX             0x18
#define SMB_WC_DELETE                     0x01
#define SMB_WC_RENAME                     0x01
#define SMB_WC_CREATE_DIRECTORY           0x00
#define SMB_WC_DELETE_DIRECTORY           0x00
#define SMB_WC_TRANS2                     0x0F

/* SMB_COM_TRANSACTION2 Words -
 * https://msdn.microsoft.com/en-us/library/ee442192.aspx */
#define SMB_NO_TDC_TRANS2                 0x0000
#define SMB_MPC_TRANS2_QUERY_PATH_INFO    0x0002
#define SMB_MPC_TRANS2_FIND_FIRST2        0x000a
#define SMB_MPC_TRANS2_DFS                0x0000
#define SMB_MDC_TRANS2                    0xffff
#define SMB_NO_MSC_TRANS2                 0x00
#define SMB_PO_TRANS2                     0x0044
#define SMB_NO_DC_TRANS2                  0x0000
#define SMB_ONE_SETUP_TRANS2              0x01
#define SMB_SETUP_TRANS2_QUERY_PATH_INFO  0x0005
#define SMB_SETUP_TRANS2_FIND_FIRST2      0x0001
#define SMB_SETUP_TRANS2_FIND_NEXT2       0x0002
#define SMB_SETUP_TRANS2_GET_DFS          0x0010

#define SMB_TRANS2_SEARCH_COUNT           0x00C8

/* QUERY Information Level Codes -
 * https://msdn.microsoft.com/en-us/library/ff470079.aspx */
#define SMB_QUERY_FILE_ALL_INFO           0x0107
#define SMB_QUERY_FILE_ALT_NAME_INFO      0x0108

/* FIND Information Level Codes -
 * https://msdn.microsoft.com/en-us/library/ff470294.aspx */
#define SMB_FIND_FILE_BOTH_DIRECTORY_INFO 0x0104

/* SMB_FILE_ATTRIBUTES -
 * https://msdn.microsoft.com/en-us/library/ee441551.aspx */
#define SMB_FILE_ATTRIBUTE_READONLY       0x0001
#define SMB_FILE_ATTRIBUTE_HIDDEN         0x0002
#define SMB_FILE_ATTRIBUTE_SYSTEM         0x0004
#define SMB_FILE_ATTRIBUTE_DIRECTORY      0x0010
#define SMB_FILE_ATTRIBUTE_ARCHIVE        0x0020

/* TRANS2_FIND_FIRST2 Trans2_Parameters Flags field */
#define SMB_FIND_CLOSE_AT_EOS             0x0002
#define SMB_FIND_RETURN_RESUME_KEYS       0x0004
#define SMB_FIND_CONTINUE_FROM_LAST       0x0008

#define SMB_FLAGS_CANONICAL_PATHNAMES     0x10
#define SMB_FLAGS_CASELESS_PATHNAMES      0x08
#define SMB_FLAGS2_UNICODE_STRINGS        0x8000
#define SMB_FLAGS2_NT_ERROR_CODES         0x4000
#define SMB_FLAGS2_IS_LONG_NAME           0x0040
#define SMB_FLAGS2_KNOWS_LONG_NAME        0x0001
#define SMB_TRANS2_FLAGS_NONE             0x0000
#define SMB_TRANS2_FLAGS_DISCONN_TID      0x0001
#define SMB_TRANS2_FLAGS_NO_RESPONSE      0x0002

#define SMB_CAP_LARGE_FILES               0x08
#define SMB_CAP_UNICODE_STRINGS           0x04
#define SMB_CAP_NT_SMBS                   0x10
#define SMB_CAP_NT_STATUS                 0x00000040
#define SMB_GENERIC_WRITE                 0x40000000
#define SMB_GENERIC_READ                  0x80000000
#define SMB_FILE_SHARE_ALL                0x07
#define SMB_FILE_OPEN                     0x01
#define SMB_FILE_OVERWRITE_IF             0x05

#define SMB_BUFFER_FORMAT_ASCII           0x04
#define SMB_NO_SEARCH_ATT                 0x0000
#define SMB_SEARCH_ATT_H_S                0x0006

/* SMB error codes - https://msdn.microsoft.com/en-us/library/ee441884.aspx */
/* ERRDOS Class 0x01 */
#define SMB_ERR_BADFILE                   0x00020001
#define SMB_ERR_BADPATH                   0x00030001
#define SMB_ERR_NOACCESS                  0x00050001
#define SMB_ERR_NOMEM                     0x00080001

/* NT STATUS codes - https://msdn.microsoft.com/en-us/library/ee441884.aspx */
#define NT_STATUS_NO_MORE_FILES           0x80000006
#define NT_STATUS_INVALID_PARAMETER       0xC000000D
#define NT_STATUS_NO_SUCH_FILE            0xC000000F
#define NT_STATUS_END_OF_FILE             0xC0000011
#define NT_STATUS_ACCESS_DENIED           0xC0000022
#define NT_STATUS_OBJECT_NAME_INVALID     0xC0000033
#define NT_STATUS_OBJECT_NAME_NOT_FOUND   0xC0000034
#define NT_STATUS_OBJECT_NAME_COLLISION   0xC0000035
#define NT_STATUS_OBJECT_PATH_NOT_FOUND   0xC000003A
#define NT_STATUS_FILE_IS_A_DIR           0xC00000BA
#define NT_STATUS_BAD_NETWORK_NAME        0xC00000CC
#define NT_STATUS_DIRECTORY_NOT_EMPTY     0xC0000101
#define NT_STATUS_NOT_A_DIRECTORY         0xC0000103
#define NT_STATUS_INSUFF_SERVER_RESOURCES 0xC0000205
#define NT_STATUS_NOT_FOUND               0xC0000225
#define NT_STATUS_PATH_NOT_COVERED        0xC0000257

struct smb_header {
  unsigned char nbt_type;
  unsigned char nbt_flags;
  unsigned short nbt_length;
  unsigned char magic[4];
  unsigned char command;
  unsigned int status;
  unsigned char flags;
  unsigned short flags2;
  unsigned short pid_high;
  unsigned char signature[8];
  unsigned short pad;
  unsigned short tid;
  unsigned short pid;
  unsigned short uid;
  unsigned short mid;
} PACK;

struct smb_negotiate_response {
  struct smb_header h;
  unsigned char word_count;
  unsigned short dialect_index;
  unsigned char security_mode;
  unsigned short max_mpx_count;
  unsigned short max_number_vcs;
  unsigned int max_buffer_size;
  unsigned int max_raw_size;
  unsigned int session_key;
  unsigned int capabilities;
  unsigned int system_time_low;
  unsigned int system_time_high;
  unsigned short server_time_zone;
  unsigned char encryption_key_length;
  unsigned short byte_count;
  char bytes[1];
} PACK;

struct andx {
  unsigned char command;
  unsigned char pad;
  unsigned short offset;
} PACK;

struct smb_setup {
  unsigned char word_count;
  struct andx andx;
  unsigned short max_buffer_size;
  unsigned short max_mpx_count;
  unsigned short vc_number;
  unsigned int session_key;
  unsigned short lengths[2];
  unsigned int pad;
  unsigned int capabilities;
  unsigned short byte_count;
} PACK;

struct smb_tree_connect {
  unsigned char word_count;
  struct andx andx;
  unsigned short flags;
  unsigned short pw_len;
  unsigned short byte_count;
} PACK;

struct smb_nt_create {
  unsigned char word_count;
  struct andx andx;
  unsigned char pad;
  unsigned short name_length;
  unsigned int flags;
  unsigned int root_fid;
  unsigned int access;
  curl_off_t allocation_size;
  unsigned int ext_file_attributes;
  unsigned int share_access;
  unsigned int create_disposition;
  unsigned int create_options;
  unsigned int impersonation_level;
  unsigned char security_flags;
  unsigned short byte_count;
} PACK;

struct smb_nt_create_response {
  struct smb_header h;
  unsigned char word_count;
  struct andx andx;
  unsigned char op_lock_level;
  unsigned short fid;
  unsigned int create_disposition;

  curl_off_t create_time;
  curl_off_t last_access_time;
  curl_off_t last_write_time;
  curl_off_t last_change_time;
  unsigned int ext_file_attributes;
  curl_off_t allocation_size;
  curl_off_t end_of_file;

} PACK;

struct smb_read {
  unsigned char word_count;
  struct andx andx;
  unsigned short fid;
  unsigned int offset;
  unsigned short max_bytes;
  unsigned short min_bytes;
  unsigned int timeout;
  unsigned short remaining;
  unsigned int offset_high;
  unsigned short byte_count;
} PACK;

struct smb_write {
  struct smb_header h;
  unsigned char word_count;
  struct andx andx;
  unsigned short fid;
  unsigned int offset;
  unsigned int timeout;
  unsigned short write_mode;
  unsigned short remaining;
  unsigned short pad;
  unsigned short data_length;
  unsigned short data_offset;
  unsigned int offset_high;
  unsigned short byte_count;
  unsigned char pad2;
} PACK;

struct smb_close {
  unsigned char word_count;
  unsigned short fid;
  unsigned int last_mtime;
  unsigned short byte_count;
} PACK;

struct smb_tree_disconnect {
  unsigned char word_count;
  unsigned short byte_count;
} PACK;

struct smb_delete {
  unsigned char word_count;
  unsigned short search_attributes;
  unsigned short byte_count;
} PACK;

struct smb_rename {
  unsigned char word_count;
  unsigned short search_attributes;
  unsigned short byte_count;
} PACK;

struct smb_mkdir {
    unsigned char word_count;
    unsigned short byte_count;
} PACK;

struct smb_deldir {
    unsigned char word_count;
    unsigned short byte_count;
} PACK;

struct smb_trans2 {
    unsigned char word_count;
    unsigned short total_parameter_count;
    unsigned short total_data_count;
    unsigned short max_parameter_count;
    unsigned short max_data_count;
    unsigned char max_setup_count;
    unsigned char reserved_1;
    unsigned short flags;
    unsigned int timeout;
    unsigned short reserved_2;
    unsigned short parameter_count;
    unsigned short parameter_offset;
    unsigned short data_count;
    unsigned short data_offset;
    unsigned char setup_count;
    unsigned char reserved_3;
    unsigned short setup;
    unsigned short byte_count;
} PACK;

struct smb_directory_info {
    unsigned int next_entry_offset;
    unsigned int file_index;
    curl_off_t creation_time;
    curl_off_t last_access_time;
    curl_off_t last_write_time;
    curl_off_t last_change_time;
    curl_off_t end_of_file;
    curl_off_t allocation_size;
    unsigned int ext_file_attributes;
    unsigned int file_name_length;
    unsigned int ea_size;
    unsigned char short_name_length;
    unsigned char reserved;
    unsigned char short_name[24];
};

#if defined(_MSC_VER) || defined(__ILEC400__)
#  pragma pack(pop)
#endif

#endif /* BUILDING_CURL_SMB_C */

#if !defined(CURL_DISABLE_SMB) && defined(USE_NTLM) && \
    (CURL_SIZEOF_CURL_OFF_T > 4)

#if !defined(USE_WINDOWS_SSPI) || defined(USE_WIN32_CRYPTO)

extern const struct Curl_handler Curl_handler_smb;
extern const struct Curl_handler Curl_handler_smbs;

#endif /* !USE_WINDOWS_SSPI || USE_WIN32_CRYPTO */

#endif /* CURL_DISABLE_SMB && USE_NTLM && CURL_SIZEOF_CURL_OFF_T > 4 */

#endif /* HEADER_CURL_SMB_H */
