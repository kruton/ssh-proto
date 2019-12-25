meta:
  id: ssh
  endian: be
  xref:
    rfc: 4253
  ks-opaque-types: true
types:
  byte_string:
    seq:
      - id: len
        type: u4
      - id: data
        size: len
  id_banner:
    seq:
      - id: prefix
        contents: SSH-
      - id: proto_version
        type: str
        encoding: UTF-8
        terminator: 10
  unencrypted_packet:
    seq:
      - id: packet_length
        type: u4
      - id: padding_length
        type: u1
      - id: payload
        type: unencrypted_payload
        size: packet_length - padding_length - 1
      - id: random_padding
        size: padding_length
  unencrypted_payload:
    seq:
      - id: message_type
        type: u1
        enum: message_type
      - id: body
        size: _parent.as<unencrypted_packet>.packet_length - _parent.as<unencrypted_packet>.padding_length - 2
        type:
          switch-on: message_type
          # This should only include messages 1-19, 20-29, 30-49.
          cases:
            'message_type::ssh_msg_kexinit': ssh_msg_kexinit
            'message_type::ssh_msg_kexdh_init': ssh_msg_kexdh_init
            'message_type::ssh_msg_kexdh_reply': ssh_msg_kexdh_reply
  encrypted_packet:
    params:
      - id: mac_length
        type: u4
        doc: |
          The length of the MAC used for encrypted packets.
    seq:
      - id: packet_length
        type: u4
      - id: encrypted_payload
        size: packet_length
      - id: mac
        size: mac_length
  ssh_msg_kexinit:
    doc-ref: RFC 4253 section 7.1
    seq:
      - id: cookie
        size: 16
      - id: kex_algorithms
        type: name_list
      - id: server_host_key_algorithms
        type: name_list
      - id: encryption_algorithms_client_to_server
        type: name_list
      - id: encryption_algorithms_server_to_client
        type: name_list
      - id: mac_algorithms_client_to_server
        type: name_list
      - id: mac_algorithms_server_to_client
        type: name_list
      - id: compression_algorithms_client_to_server
        type: name_list
      - id: compression_algorithms_server_to_client
        type: name_list
      - id: languages_client_to_server
        type: name_list
      - id: languages_server_to_client
        type: name_list
      - id: first_kex_packet_follows
        type: u1
  ssh_msg_newkeys:
    doc-ref: RFC 4253 section 7.2
    doc: This type has no payload
  ssh_msg_kexdh_init:
    doc-ref: RFC 4253 section 8
    seq:
      - id: e
        type: mpint
  ssh_msg_kexdh_reply:
    doc-ref: RFC 4253 section 8
    seq:
      - id: server_key
        type: byte_string
      - id: f
        type: mpint
      - id: signature_h
        type: byte_string
  kexdh_hash:
    doc-ref: RFC 4253 section 8
    seq:
      - id: v_c
        doc: the client's identification string
        type: byte_string
      - id: v_s
        doc: the server's identification string
        type: byte_string
      - id: i_c
        doc: the payload of the client's SSH_MSG_KEXINIT
        type: byte_string
      - id: i_s
        doc: the payload of the server's SSH_MSG_KEXINIT
        type: byte_string
      - id: k_s
        doc: the host key
        type: byte_string
      - id: e
        doc: exchange value sent by the client
        type: mpint
      - id: f
        doc: exchange value sent by the server
        type: mpint
      - id: k
        doc: the shared secret
        type: mpint

enums:
  message_type:
    1: ssh_msg_disconnect
    2: ssh_msg_ignore
    3: ssh_msg_unimplemented
    4: ssh_msg_debug
    5: ssh_msg_service_request
    6: ssh_msg_service_accept
    7: ssh_msg_ext_info
    8: ssh_msg_newcompress
    20: ssh_msg_kexinit
    21: ssh_msg_newkeys
    30: ssh_msg_kexdh_init
    31: ssh_msg_kexdh_reply
    # Types after here should not appear in unencrypted messages.
    50: ssh_msg_userauth_request
    51: ssh_msg_userauth_failure
    52: ssh_msg_userauth_success
    53: ssh_msg_userauth_banner
    60: ssh_msg_userauth_info_request
    61: ssh_msg_userauth_info_response
    80: ssh_msg_global_request
    81: ssh_msg_request_success
    82: ssh_msg_request_failure
    90: ssh_msg_channel_open
    91: ssh_msg_channel_open_confirmation
    92: ssh_msg_channel_open_failure
    93: ssh_msg_channel_window_adjust
    94: ssh_msg_channel_data
    95: ssh_msg_channel_extended_data
    96: ssh_msg_channel_eof
    97: ssh_msg_channel_close
    98: ssh_msg_channel_request
    99: ssh_msg_channel_success
    100: ssh_msg_channel_failure
  disconnect_reason:
    1: ssh_disconnect_host_not_allowed_to_connect
    2: ssh_disconnect_protocol_error
    3: ssh_disconnect_key_exchange_failed
    4: ssh_disconnect_reserved
    5: ssh_disconnect_mac_error
    6: ssh_disconnect_compression_error
    7: ssh_disconnect_service_not_available
    8: ssh_disconnect_protocol_version_not_supported
    9: ssh_disconnect_host_key_not_verifiable
    10: ssh_disconnect_connection_lost
    11: ssh_disconnect_by_application
    12: ssh_disconnect_too_many_connections
    13: ssh_disconnect_auth_cancelled_by_user
    14: ssh_disconnect_no_more_auth_methods_available
    15: ssh_disconnect_illegal_user_name
  channel_connection_failure_reason:
    1: ssh_open_administratively_prohibited
    2: ssh_open_connect_failed
    3: ssh_open_unknown_channel_type
    4: ssh_open_resource_shortage
  publickey_subsystem_status:
    0: ssh_publickey_success
    1: ssh_publickey_access_denied
    2: ssh_publickey_storage_exceeded
    3: ssh_publickey_version_not_supported
    4: ssh_publickey_key_not_found
    5: ssh_publickey_key_not_supported
    6: ssh_publickey_key_already_present
    7: ssh_publickey_general_failure
    8: ssh_publickey_request_not_supported
    9: ssh_publickey_attribute_not_supported
