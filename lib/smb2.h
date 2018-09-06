#ifndef HEADER_CURL_SMB2_H
#define HEADER_CURL_SMB2_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2018
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

#if defined(_MSC_VER) || defined(__ILEC400__)
#  define PACK
#  pragma pack(push)
#  pragma pack(1)
#elif defined(__GNUC__)
#  define PACK __attribute__((packed))
#else
#  define PACK
#endif

/* SMB2 Op Codes */
#define SMB2_COM_NEGOTIATE                0x0000
#define SMB2_COM_SESSION_SETUP            0x0001
#define SMB2_COM_LOGOFF                   0x0002
#define SMB2_COM_TREE_CONNECT             0x0003
#define SMB2_COM_TREE_DISCONNECT          0x0004
#define SMB2_COM_CREATE                   0x0005
#define SMB2_COM_CLOSE                    0x0006
#define SMB2_COM_READ                     0x0008
#define SMB2_COM_WRITE                    0x0009
#define SMB2_COM_IOCTL                    0x000B
#define SMB2_COM_QUERY_DIRECTORY          0x000E
#define SMB2_COM_SET_INFO                 0x0011

enum compound_state {
  NOT_COMPOUND = 0,
  FIRST_COMPOUND,
  SUBSEQUENT_COMPOUND,
  LAST_COMPOUND
};

struct net_bios_header {
    unsigned char nbt_type;
    unsigned char nbt_flags;
    unsigned short nbt_length;
} PACK;

struct smb2_header {
    unsigned char protocol_id[4];
    unsigned short structure_size;
    unsigned short credit_charge;
    uint32_t status;
    unsigned short command;
    unsigned short credit_rx;
    uint32_t flags;
    uint32_t next_command;
    uint64_t message_id;
    uint32_t reserved;
    uint32_t tree_id;
    uint64_t session_id;
    unsigned char signature[16];
} PACK;

struct smb2_negotiate_request {
    unsigned short structure_size;
    unsigned short dialect_count;
    unsigned short security_mode;
    unsigned short reserved;
    uint32_t capabilities;
    unsigned char client_guid[16];
    uint64_t client_start_time;
} PACK;

struct smb2_negotiate_response {
    struct net_bios_header netbios;
    struct smb2_header h2;
    unsigned short structure_size;
    unsigned short security_mode;
    unsigned short dialect_revision;
    unsigned short reserved;
    unsigned char server_guid[16];
    uint32_t capabilities;
    uint32_t max_transact_size;
    uint32_t max_read_size;
    uint32_t max_write_size;
    uint64_t system_time;
    uint64_t server_start_time;
    unsigned short security_buffer_offset;
    unsigned short security_buffer_length;
    uint32_t reserved2;
} PACK;

struct smb2_session_setup_request {
    unsigned short structure_size;
    unsigned char flags;
    unsigned char security_mode;
    uint32_t capabilities;
    uint32_t channel;
    unsigned short security_buffer_offset;
    unsigned short security_buffer_length;
    uint64_t previous_session_id;
} PACK;

struct smb2_session_setup_response {
    struct net_bios_header netbios;
    struct smb2_header h2;
    unsigned short structure_size;
    unsigned short session_flags;
    unsigned short security_buffer_offset;
    unsigned short security_buffer_length;
    /* NTLM Secure Service Provider */
    uint64_t identifier;
    uint32_t message_type;
} PACK;

struct smb2_tree_connect_request {
    unsigned short structure_size;
    unsigned short reserved;
    unsigned short path_offset;
    unsigned short path_length;
} PACK;

struct smb2_create_request {
    unsigned short structure_size;
    unsigned char security_flags;
    unsigned char requested_oplock_level;
    uint32_t impersonation_level;
    uint64_t smb_create_flags;
    uint64_t reserved;
    uint32_t desired_access;
    uint32_t file_attributes;
    uint32_t share_access;
    uint32_t create_disposition;
    uint32_t create_options;
    unsigned short name_offset;
    unsigned short name_length;
    uint32_t create_contexts_offset;
    uint32_t create_contexts_length;
} PACK;

struct smb2_create_response {
    struct net_bios_header netbios;
    struct smb2_header h2;
    unsigned short structure_size;
    unsigned char oplock_level;
    unsigned char flags;
    uint32_t create_action;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t change_time;
    uint64_t allocation_size;
    uint64_t end_of_file;
    uint32_t file_attributes;
    uint32_t reserved2;
    unsigned char file_id[16];
    uint32_t create_contexts_offset;
    uint32_t create_contexts_length;
} PACK;

struct smb2_set_info_request {
    unsigned short structure_size;
    unsigned char info_type;
    unsigned char file_info_class;
    uint32_t buffer_length;
    unsigned short buffer_offset;
    unsigned short reserved;
    uint32_t additional_information;
    unsigned char file_id[16];
} PACK;

struct smb2_query_directory_request {
    unsigned short structure_size;
    unsigned char file_info_class;
    unsigned char flags;
    uint32_t file_index;
    unsigned char file_id[16];
    unsigned short file_name_offset;
    unsigned short file_name_length;
    uint32_t output_buffer_length;
} PACK;

struct smb2_query_directory_response {
    struct net_bios_header netbios;
    struct smb2_header h2;
    unsigned short structure_size;
    unsigned short output_buffer_offset;
    unsigned short output_buffer_length;
} PACK;

struct smb2_read_request {
    unsigned short structure_size;
    unsigned char padding;
    unsigned char flags;
    uint32_t length;
    uint64_t offset;
    unsigned char file_id[16];
    uint32_t min_count;
    uint32_t channel;
    uint32_t remaining_bytes;
    unsigned short read_channel_info_offset;
    unsigned short read_channel_info_length;
} PACK;

struct smb2_read_response {
    struct net_bios_header netbios;
    struct smb2_header h2;
    unsigned short structure_size;
    unsigned char data_offset;
    unsigned char reserved;
    uint32_t data_length;
    uint32_t data_remaining;
    uint32_t reserved2;
} PACK;

struct smb2_write_request {
  unsigned short structure_size;
  unsigned short data_offset;
  uint32_t length;
  uint64_t offset;
  unsigned char file_id[16];
  uint32_t channel;
  uint32_t remaining_bytes;
  unsigned short write_channel_info_offset;
  unsigned short write_channel_info_length;
  uint32_t flags;
} PACK;

struct smb2_write_response {
  struct net_bios_header netbios;
  struct smb2_header h2;
  unsigned short structure_size;
  unsigned short reserved;
  uint32_t count;
  uint32_t remaining;
  unsigned short write_channel_info_offset;
  unsigned short write_channel_info_length;
} PACK;

struct smb2_close_request {
    unsigned short structure_size;
    unsigned short flags;
    uint32_t reserved;
    unsigned char file_id[16];
} PACK;

struct smb2_close_response {
    struct smb2_header h2;
    unsigned short structure_size;
    unsigned short flags;
    uint32_t reserved;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t change_time;
    uint64_t allocation_size;
    uint64_t end_of_file;
    uint32_t file_attributes;
} PACK;

struct smb2_tree_disconnect_request {
    unsigned short structure_size;
    unsigned short reserved;
} PACK;

struct smb2_logoff_request {
    unsigned short structure_size;
    unsigned short reserved;
} PACK;

struct smb2_ioctl_request {
  unsigned short structure_size;
  unsigned short reserved;
  uint32_t ctl_code;
  unsigned char file_id[16];
  uint32_t input_offset;
  uint32_t input_count;
  uint32_t max_input_response;
  uint32_t output_offset;
  uint32_t output_count;
  uint32_t max_output_response;
  uint32_t flags;
  uint32_t reserved2;
} PACK;

struct smb2_ioctl_response {
  struct net_bios_header netbios;
  struct smb2_header h2;
  unsigned short structure_size;
  unsigned short reserved;
  uint32_t ctl_code;
  unsigned char file_id[16];
  uint32_t input_offset;
  uint32_t input_count;
  uint32_t output_offset;
  uint32_t output_count;
  uint32_t flags;
  uint32_t reserved2;
} PACK;

struct ntlmssp {
    uint64_t identifier;
    uint32_t msg_type;
    uint16_t lm_len;
    uint16_t lm_max;
    uint32_t lm_off;
    uint16_t nt_len;
    uint16_t nt_max;
    uint32_t nt_off;
    uint16_t dom_len;
    uint16_t dom_max;
    uint32_t dom_off;
    uint16_t usr_len;
    uint16_t usr_max;
    uint32_t usr_off;
    uint16_t grp_len;
    uint16_t grp_max;
    uint32_t grp_off;
    uint16_t skey_len;
    uint16_t skey_max;
    uint32_t skey_off;
    uint32_t neg_flags;
} PACK;

struct smb2_file_directory_info {
    uint32_t next_entry_offset;
    uint32_t file_index;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t last_change_time;
    uint64_t end_of_file;
    uint64_t allocation_size;
    uint32_t file_attributes;
    uint32_t file_name_length;
} PACK;

struct smb2_file_rename_information {
  char replace_if_exists;
  char reserved[7];
  uint64_t root_directory;
  uint32_t file_name_length;
} PACK;

struct smb2_req_get_dfs_referral {
  unsigned short max_referral_level;
} PACK;

struct smb2_resp_get_dfs_referral {
  unsigned short path_consumed;
  unsigned short number_of_referrals;
  uint32_t referral_header_flags;
} PACK;

struct smb2_dfs_referral_entry {
  unsigned short version_number;
  unsigned short size;
  unsigned short server_type;
  unsigned short referral_entry_flags;
} PACK;

struct smb2_dfs_referral_v2 {
  struct smb2_dfs_referral_entry entry;
  uint32_t proximity;
  uint32_t time_to_live;
  unsigned short dfs_path_offset;
  unsigned short dfs_alternate_path_offset;
  unsigned short network_address_offset;
} PACK;

struct smb2_dfs_referral_v3 {
  struct smb2_dfs_referral_entry entry;
  uint32_t time_to_live;
  unsigned short dfs_path_offset;
  unsigned short dfs_alternate_path_offset;
  unsigned short network_address_offset;
  unsigned char ServiceSiteGuid[16];
} PACK;

/* SMB v2 Create Request Impersonation Level */
/* https://msdn.microsoft.com/en-us/library/cc246502.aspx */
#define SMB2_IMPERSONATION_ANONYMOUS      0x00000000
#define SMB2_IMPERSONATION_IMPERSONATE    0x00000002

/* SMB v2 Desired Access/Access Mask Values (Directory_Access_Mask) */
/* https://msdn.microsoft.com/en-us/library/cc246801.aspx */
#define SMB2_FILE_LIST_DIRECTORY          0x00000001
#define SMB2_FILE_ADD_FILE                0x00000002
#define SMB2_FILE_ADD_SUBDIRECTORY        0x00000004
#define SMB2_FILE_TRAVERSE                0x00000020

/* SMB v2 Desired Access/Access Mask Values (File_Pipe_Printer_Access_Mask) */
/* https://msdn.microsoft.com/en-us/library/cc246802.aspx */
#define SMB2_FILE_READ_DATA               0x00000001
#define SMB2_FILE_WRITE_DATA              0x00000002
#define SMB2_FILE_APPEND_DATA             0x00000004
#define SMB2_FILE_READ_EA                 0x00000008
#define SMB2_FILE_WRITE_EA                0x00000010
#define SMB2_FILE_EXECUTE                 0x00000020
#define SMB2_FILE_DELETE_CHILD            0x00000040
#define SMB2_FILE_READ_ATTRIBUTES         0x00000080
#define SMB2_FILE_WRITE_ATTRIBUTES        0x00000100
#define SMB2_DELETE                       0x00010000
#define SMB2_READ_CONTROL                 0x00020000
#define SMB2_WRITE_DAC                    0x00040000
#define SMB2_WRITE_OWNER                  0x00080000
#define SMB2_SYNCHRONIZE                  0x00100000
#define SMB2_ACCESS_SYSTEM_SECURITY       0x01000000
#define SMB2_MAXIMUM_ALLOWED              0x02000000
#define SMB2_GENERIC_ALL                  0x10000000
#define SMB2_GENERIC_EXECUTE              0x20000000
#define SMB2_GENERIC_WRITE                0x40000000
#define SMB2_GENERIC_READ                 0x80000000

/* SMB v2 Create Request FileAttributes values */
/* https://msdn.microsoft.com/en-us/library/cc232110.aspx */
#define SMB2_FILE_SEQUENTIAL_ONLY         0x00000004
#define SMB2_FILE_ATTRIBUTE_DIRECTORY     0x00000010
#define SMB2_FILE_ATTRIBUTE_NORMAL        0x00000080

/* SMB v2 Create Request ShareAccess values */
/* https://msdn.microsoft.com/en-us/library/cc246502.aspx */
#define SMB2_FILE_SHARE_READ              0x00000001
#define SMB2_FILE_SHARE_WRITE             0x00000002
#define SMB2_FILE_SHARE_DELETE            0x00000004

/* SMB v2 Create Request CreateDisposition values */
/* https://msdn.microsoft.com/en-us/library/cc246502.aspx */
#define SMB2_FILE_SUPERSEDE               0x00000000
#define SMB2_FILE_OPEN                    0x00000001
#define SMB2_FILE_CREATE                  0x00000002
#define SMB2_FILE_OPEN_IF                 0x00000003
#define SMB2_FILE_OVERWRITE               0x00000004
#define SMB2_FILE_OVERWRITE_IF            0x00000005

/* SMB v2 Create Request CreateOptions values */
/* https://msdn.microsoft.com/en-us/library/cc246502.aspx */
#define SMB2_FILE_DIRECTORY_FILE          0x00000001
#define SMB2_FILE_NON_DIRECTORY_FILE      0x00000040

/* SMB v2 Query Directory Request */
/* https://msdn.microsoft.com/en-us/library/cc246551.aspx */
/* File Information Class Values */
#define SMB2_FILE_DIRECTORY_INFORMATION         0x01
#define SMB2_FILE_FULL_DIRECTORY_INFORMATION    0x02
#define SMB2_FILE_BOTH_DIRECTORY_INFORMATION    0x03
#define SMB2_FILE_NAMES_INFORMATION             0x0C
#define SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION 0x25

/* SMBv2 Signing and negotiation */
#define NTLMSSP_SIGNATURE "\x4e\x54\x4c\x4d\x53\x53\x50"
#define NTLMSSP_MESSAGE_TYPE              0x00000003
#define NTLMSSP_NEGOTIATE_KEY_EXCH        0x40000000
#define NTLMSSP_NEGOTIATE_128             0x20000000
#define NTLMSSP_NEGOTIATE_VERSION         0x02000000
#define NTLMSSP_NEGOTIATE_TARGET_INFO     0x00800000
#define NTLMSSP_NEGOTIATE_DOMAIN          0x00010000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN     0x00008000
#define NTLMSSP_NEGOTIATE_ANONYMOUS       0x00000800
#define NTLMSSP_NEGOTIATE_SIGN            0x00000010
#define NTLMSSP_NEGOTIATE_OEM             0x00000002
#define NTLMSSP_NEGOTIATE_UNICODE         0x00000001

#define RESP_KEY_NT_LEN                   16
#define NT_PROOF_STR_LEN                  16
#define EXPORTED_KEY_LEN                  16
#define SIGNATURE_LEN                     16
#define RANDOM_SESSION_KEY_LEN            16
#define HMAC_SHA256_LEN                   32
#define AES_128_CMAC_LEN                  16

/* SMBv2 Negotiate Response */
#define SMB2_GLOBAL_CAP_LARGE_MTU         0x00000004

/* SMB v2 Close Request optional flag */
/* https://msdn.microsoft.com/en-us/library/cc246523.aspx */
#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB  0x0001

/* SMB v2 Session Setup Response */
#define STATUS_MORE_PROCESSING_REQUIRED   0xC0000016
#define SMB2_GLOBAL_CAP_DFS               0x00000001

/* SMB v2 Session Setup Request */
#define SMB2_NEGOTIATE_SIGNING_ENABLED    0x01

/* SMB v2 Set Info Request */
#define SMB2_INFO_FILE                    0x01

/* SMB v2 SMB2 Header Request */
#define SMB2_FLAGS_RELATED_OPERATIONS     0x00000004
#define SMB2_FLAGS_SIGNED                 0x00000008

/* SMB v2 IOCTL Request */
#define FSCTL_DFS_GET_REFERRALS           0x00060194
#define SMB2_0_IOCTL_IS_FSCTL             0x00000001
#define DFSV3_NAME_LIST_REFERRAL          0x0002

/* SMB v2 Dialects */
#define SMB202_DIALECT                    0x0202
#define SMB210_DIALECT                    0x0210
#define SMB2FF_DIALECT                    0x02FF
#define SMB300_DIALECT                    0x0300
#define SMB302_DIALECT                    0x0302
#define SMB311_DIALECT                    0x0311 /* Currently unsupported */

#endif /* HEADER_CURL_SMB2_H */
