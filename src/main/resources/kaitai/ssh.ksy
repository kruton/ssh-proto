meta:
  id: ssh
  title: SSH
  endian: be
  xref:
    rfc: 4253
  license: CC0-1.0
types:
  name_entry:
    seq:
      - id: data
        type: str
        terminator: 0x2C
        encoding: ascii
        eos-error: false
        repeat: eos
  name_list:
    seq:
      - id: len
        type: u4
      - id: entries
        type: name_entry
        size: len
  mpint:
    doc: |
      Big integers serialization format used by SSH.
    doc-ref: |
      https://tools.ietf.org/html/rfc4251#section-5
    seq:
      - id: len
        type: u4
      - id: body
        size: len
    instances:
      length_in_bits:
        value: (len - 1) * 8
        doc: |
          Length of big integer in bits. In OpenSSH sources, this corresponds to
          `BN_num_bits` function.
  byte_string:
    doc: |
      An integer-prefixed byte array designed to be used for arbitrary data
      that is not expected to be a string.
    -webide-representation: '{value}'
    seq:
      - id: len
        type: u4
      - id: data
        size: len
  utf8string:
    -webide-representation: '{value}'
    seq:
      - id: len
        type: u4
      - id: value
        type: str
        size: len
        encoding: UTF-8
  cstring:
    doc: |
      A integer-prefixed string designed to be read using `sshbuf_get_cstring`
      and written by `sshbuf_put_cstring` routines in ssh sources. Name is an
      obscure misnomer, as typically "C string" means a null-terminated string.
    doc-ref: 'https://github.com/openssh/openssh-portable/blob/master/sshbuf-getput-basic.c#L181'
    -webide-representation: '{value}'
    seq:
      - id: len
        type: u4
      - id: value
        type: str
        size: len
        encoding: ASCII
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
            'message_type::ssh_msg_disconnect': ssh_msg_disconnect
            'message_type::ssh_msg_ignore': ssh_msg_ignore
            'message_type::ssh_msg_unimplemented': ssh_msg_unimplemented
            'message_type::ssh_msg_service_request': ssh_msg_service_request
            'message_type::ssh_msg_service_accept': ssh_msg_service_accept
            'message_type::ssh_msg_debug': ssh_msg_debug
            'message_type::ssh_msg_kexinit': ssh_msg_kexinit
            _: invalid_message
  userauth_keyboard_interactive_payload:
    seq:
      - id: message_type
        type: u1
        enum: message_userauth_keyboard_interactive
      - id: body
        size-eos: true
        type:
          switch-on: message_type
          cases:
            'message_userauth_keyboard_interactive::ssh_msg_userauth_info_request': ssh_msg_userauth_info_request
            'message_userauth_keyboard_interactive::ssh_msg_userauth_info_response': ssh_msg_userauth_info_response
            _: invalid_message
  kexdh_payload:
    seq:
      - id: message_type
        type: u1
        enum: kex_dh
      - id: body
        size-eos: true
        type:
          switch-on: message_type
          cases:
            'kex_dh::ssh_msg_kexdh_init': ssh_msg_kexdh_init
            'kex_dh::ssh_msg_kexdh_reply': ssh_msg_kexdh_reply
            _: invalid_message
  kex_dh_gex_payload:
    seq:
      - id: message_type
        type: u1
        enum: kex_dh_gex
      - id: body
        size-eos: true
        type:
          switch-on: message_type
          cases:
            'kex_dh_gex::ssh_msg_kex_dh_gex_request_old': ssh_msg_kex_dh_gex_request_old
            'kex_dh_gex::ssh_msg_kex_dh_gex_request': ssh_msg_kex_dh_gex_request
            'kex_dh_gex::ssh_msg_kex_dh_gex_group': ssh_msg_kex_dh_gex_group
            'kex_dh_gex::ssh_msg_kex_dh_gex_init': ssh_msg_kex_dh_gex_init
            'kex_dh_gex::ssh_msg_kex_dh_gex_reply': ssh_msg_kex_dh_gex_reply
            _: invalid_message
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
  decrypted_packet:
    seq:
      - id: padding_length
        type: u1
      - id: payload
        type: decrypted_payload
        size: _parent.as<encrypted_packet>.packet_length - padding_length - 1
      - id: random_padding
        size: padding_length
  decrypted_payload:
    seq:
      - id: message_type
        type: u1
        enum: message_type
      - id: body
        size: _parent.as<decrypted_packet>._parent.as<encrypted_packet>.packet_length - _parent.as<decrypted_packet>.padding_length - 2
        type:
          switch-on: message_type
          # This should only include messages 50 and higher.
          cases:
            'message_type::ssh_msg_userauth_request': ssh_msg_userauth_request
            'message_type::ssh_msg_userauth_failure': ssh_msg_userauth_failure
            'message_type::ssh_msg_userauth_success': ssh_msg_userauth_success
            'message_type::ssh_msg_userauth_banner': ssh_msg_userauth_banner
            'message_type::ssh_msg_global_request': ssh_msg_global_request
            'message_type::ssh_msg_request_success': ssh_msg_request_success
            'message_type::ssh_msg_request_failure': ssh_msg_request_failure
            'message_type::ssh_msg_channel_open': ssh_msg_channel_open
            'message_type::ssh_msg_channel_open_confirmation': ssh_msg_channel_open_confirmation
            'message_type::ssh_msg_channel_open_failure': ssh_msg_channel_open_failure
            'message_type::ssh_msg_channel_window_adjust': ssh_msg_channel_window_adjust
            'message_type::ssh_msg_channel_data': ssh_msg_channel_data
            'message_type::ssh_msg_channel_extended_data': ssh_msg_channel_extended_data
            'message_type::ssh_msg_channel_eof': ssh_msg_channel_eof
            'message_type::ssh_msg_channel_close': ssh_msg_channel_close
            'message_type::ssh_msg_channel_request': ssh_msg_channel_request
            'message_type::ssh_msg_channel_success': ssh_msg_channel_success
            'message_type::ssh_msg_channel_failure': ssh_msg_channel_failure
            _: invalid_message
  etm_mac:
    seq:
      - id: sequence_number
        type: u4
      - id: packet_length
        type: u4
      - id: encrypted_packet
        size: packet_length
  invalid_message:
    doc: |
      This type is created when the message is not supported. This should
      cause an immediate disconnect.
  ssh_msg_disconnect:
    doc-ref: RFC 4253 section 11.1
    doc: |
      This message causes an immediate termination of the connection. After
      this message, the sender must not send or receiver data. The receiver
      must not accept any data after receiving this message.
    seq:
      - id: reason_code
        doc: machine-readable reason for disconnection
        enum: disconnect_reason
        type: u4
      - id: description
        doc: human readable reason for disconnection in ISO-10646 UTF-8
        type: utf8string
      - id: language
        doc: language tag according to RFC 3066
        type: cstring
  ssh_msg_ignore:
    doc-ref: RFC 4253 section 11.2
    doc: |
      This is a message that must be ignored. It can be used to defeat traffic
      analysis.
    seq:
      - id: data
        type: byte_string
  ssh_msg_unimplemented:
    doc-ref: RFC 4253 section 11.4
    doc: This is sent in reply to an unknown packet type.
    seq:
      - id: packet_sequence
        doc: Indicates the packet sequence number that was unrecognized.
        type: u4
  ssh_msg_debug:
    doc-ref: RFC 4253 section 11.3
    doc: |
      This is a debug message that may help with debugging the connection. If
      "always_display" is true, then this message should always be displayed.
      Otherwise it should only be displayed if the user specifically requested
      debugging output.
    seq:
      - id: always_display
        type: u1
      - id: message
        doc: debug message in ISO-10646 UTF-8 encoding
        type: utf8string
      - id: language
        doc: language tag according to RFC 3066
        type: cstring
  ssh_msg_service_request:
    doc-ref: RFC 4253 section 10
    seq:
      - id: service_name
        type: cstring
  ssh_msg_service_accept:
    doc-ref: RFC 4253 section 10
    seq:
      - id: service_name
        type: cstring
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
    doc: Diffie-Hellman key exchange initialization packet
    seq:
      - id: e
        doc: |
          Client's public key portion of ephemeral Diffie-Hellman key exchange
          (i.e., e = g^x mod p).
        type: mpint
  ssh_msg_kexdh_reply:
    doc-ref: RFC 4253 section 8
    doc: Diffie-Hellman key exchange reply packet
    seq:
      - id: server_key
        doc: Server's key (K_S) in the appropriate format.
        type: byte_string
      - id: f
        doc: |
          Server's public key portion of ephemeral Diffie-Hellman key exchange
          (i.e., f = g^y mod p).
        type: mpint
      - id: signature_h
        doc: |
          Signature over hash of the connection details. For the server,
          K = e^y mod p. See "kexdh_hash" type for contents of the hash.
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
  ssh_msg_kex_dh_gex_request_old:
    doc-ref: RFC 4419 section 5
    seq:
      - id: n
        type: u4
        doc: preferred size in bits of the group the server will send
  ssh_msg_kex_dh_gex_request:
    doc-ref: RFC 4419 section 3
    seq:
      - id: min
        type: u4
        doc: minimal size in bits of an acceptable broup
      - id: n
        type: u4
        doc: preferred size in bits of the group the server will send
      - id: max
        type: u4
        doc: maximal size in bits of an acceptable group
  ssh_msg_kex_dh_gex_group:
    doc-ref: RFC 4419 section 3
    seq:
      - id: p
        type: mpint
        doc: safe prime
      - id: g
        type: mpint
        doc: generator for subgroup GF(p)
  ssh_msg_kex_dh_gex_init:
    doc-ref: RFC 4419 section 3
    seq:
      - id: e
        type: mpint
        doc: e = g^x mod p
  ssh_msg_kex_dh_gex_reply:
    doc-ref: RFC 4419 section 3
    seq:
      - id: server_public_host_key
        type: byte_string
        doc: server public host key and certificates (K_S)
      - id: f
        type: mpint
      - id: signature_h
        type: byte_string
        doc: signature of H
  kex_dh_gex_old_hash:
    doc: This is the old exchange hash input used to authenticate the key.
    doc-ref: RFC 4419 section 3 and 5
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
      - id: n
        type: u4
        doc: preferred size in bits of the group the server will send
      - id: p
        type: mpint
        doc: safe prime
      - id: g
        type: mpint
        doc: generator for subgroup GF(p)
      - id: e
        doc: exchange value sent by the client
        type: mpint
      - id: f
        doc: exchange value sent by the server
        type: mpint
      - id: k
        doc: the shared secret
        type: mpint
  kex_dh_gex_hash:
    doc: This is the exchange hash input used to authenticate the key.
    doc-ref: RFC 4419 section 3
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
      - id: min
        type: u4
        doc: minimal size in bits of an acceptable broup
      - id: n
        type: u4
        doc: preferred size in bits of the group the server will send
      - id: max
        type: u4
        doc: maximal size in bits of an acceptable group
      - id: p
        type: mpint
        doc: safe prime
      - id: g
        type: mpint
        doc: generator for subgroup GF(p)
      - id: e
        doc: exchange value sent by the client
        type: mpint
      - id: f
        doc: exchange value sent by the server
        type: mpint
      - id: k
        doc: the shared secret
        type: mpint
  ssh_msg_kexrsa_pubkey:
    doc-ref: RFC 4432 section 4
    seq:
      - id: server_public
        type: byte_string
        doc: server public host key and certificate (K_S)
      - id: transient_key
        type: byte_string
        doc: K_T, transient RSA public key
  ssh_msg_kexrsa_secret:
    doc-ref: RFC 4432 section 4
    seq:
      - id: encrypted_k
        type: mpint
        doc: RSAES-OAEP-ENCRYPT(K_T, K); where K is the shared secret
  ssh_msg_kexrsa_done:
    doc-ref: RFC 4432 section 4
    seq:
      - id: signature_h
        type: byte_string
        doc: signature of H with the host key
  kexrsa_hash:
    doc: |
      This value is called the exchange hash, and it is used to
      authenticate the key exchange. The exchange hash SHOULD be
      kept secret.
    doc-ref: RSA 4432 section 4
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
      - id: k_t
        doc: the transient RSA key
        type: byte_string
      - id: encrypted_secret
        doc: RSAES_OAEP_ENCRYPT(K_T, K), the encrypted secret
        type: byte_string
      - id: k
        doc: the shared secret
        type: mpint
  ssh_msg_userauth_request:
    doc-ref: RFC 4252 section 5
    seq:
      - id: user_name
        type: cstring
      - id: service_name
        type: cstring
      - id: method_name_length
        type: u4
      - id: method_name
        type: str
        size: method_name_length
        encoding: ASCII
      - id: method_specific_fields
        type:
          switch-on: method_name
          cases:
            '"publickey"': userauth_request_publickey
            '"password"': userauth_request_password
            '"hostbased"': userauth_request_hostbased
            '"none"': userauth_request_none
            '"keyboard-interactive"': userauth_request_keyboard_interactive
            '"gssapi-with-mic"': userauth_request_gssapi_with_mic
            '"gssapi-keyex"': userauth_request_gssapi_keyex
            '"gssapi"': userauth_request_gssapi
            '"external-keyx"': userauth_request_external_keyx
            _: invalid_message
  userauth_request_publickey:
    doc-ref: RFC 4252 section 7
    seq:
      - id: always_false
        contents: [0]
      - id: public_key_algorithm_name
        type: cstring
      - id: public_key_blob
        type: byte_string
  userauth_request_password:
    doc-ref: RFC 4252 section 8
    seq:
      - id: change_password
        type: u1
      - id: plaintext_password
        type: utf8string
        doc: plaintext password in UTF-8
      - id: new_plaintext_password
        type: utf8string
        doc: new password in UTF-8
        if: change_password != 0
  userauth_request_hostbased:
    doc-ref: RFC 4252 section 9
    seq:
      - id: algorithm
        type: cstring
        doc: public key algorithm for host key
      - id: host_key
        type: byte_string
        doc: public host key and certificates for client host
      - id: client_host_name
        type: byte_string
        doc: client host name expressed as the FQDN in US-ASCII
      - id: user_name
        type: utf8string
        doc: user name on the client host in UTF-8
  userauth_request_none:
    doc: |
      This should be sent to the server to trigger the server to tell which
      methods may continue.
    doc-ref: RFC 4252 section 5.2
  userauth_request_keyboard_interactive:
    doc-ref: RFC 4256 section 3.1
    seq:
      - id: language_tag
        type: byte_string
      - id: submethods
        type: byte_string
  userauth_request_gssapi_with_mic:
    doc-ref: RFC 4462 section 3.2
    seq:
      - id: number_of_mechanisms
        type: u4
        doc: The number of mechanism OIDs client supports
      - id: mechanisms
        type: byte_string
        repeat: expr
        repeat-expr: number_of_mechanisms
        doc: Mechanism OIDs encoded as ASN.1 DER rules
  userauth_request_gssapi_keyex:
    doc-ref: RFC 4462 section 4
    seq:
      - id: mic
        type: byte_string
        doc: Obtained by calling GSS_GetMIC over gssapi_keyex_hash
  gssapi_keyex_hash:
    doc-ref: RFC 4462 section 4
    seq:
      - id: session_identifier
        type: byte_string
      - id: request_identifier
        contents: [50] # ==SSH_MSG_USERAUTH_REQUEST
      - id: user_name
        type: byte_string
      - id: service_name
        type: byte_string
      - id: request_type
        contents: gssapi-keyex
  userauth_request_gssapi:
    doc-ref: RFC 4462
    doc: TODO
  userauth_request_external_keyx:
    doc-ref: RFC 4462
    doc: TODO
  ssh_msg_userauth_failure:
    doc-ref: RFC 4252 section 5.1
    seq:
      - id: valid_authentications
        type: name_list
        doc: Authentication methods that can continue
      - id: partial_success
        type: u1
  ssh_msg_userauth_success:
    doc-ref: RFC 4252 section 5.1
  ssh_msg_userauth_banner:
    doc-ref: RFC 4252 section 5.4
    seq:
      - id: message
        type: utf8string
        doc: banner message in UTF-8 encoding
      - id: language_tag
        type: byte_string
        doc: language tag in RFC 3066 format
  ssh_msg_global_request:
    doc-ref: RFC 4254 section 4
    seq:
      - id: request_name_length
        type: u4
      - id: request_name
        type: str
        size: request_name_length
        encoding: ASCII
      - id: want_reply
        type: u1
      - id: request_specific_fields
        type:
          switch-on: request_name
          cases:
            '"tcpip-forward"': global_request_tcpip_forward
            '"cancel-tcpip-forward"': global_request_cancel_tcpip_forward
            #'"streamlocal-forward@openssh.com"': global_request_streamlocal_forward_openssh # TODO
            #'"cancel-streamlocal-forward@openssh.com"': global_request_cancel_streamlocal_forward_openssh # TODO
            #'"hostkeys-00@openssh.com"': global_request_hostkeys_00_openssh # TODO
            #'"hostkeys-prove-00@openssh.com"': global_request_hostkeys_prove_00_openssh # TODO
            _: invalid_message
  global_request_tcpip_forward:
    doc-ref: RFC 4254 section 7.1
    seq:
      - id: address_to_bind
        type: byte_string
        doc: Address to bind (e.g., "0.0.0.0")
      - id: port_to_bind
        type: u4
        doc: Port number to bind
  global_request_cancel_tcpip_forward:
    doc-ref: RFC 4254 section 7.1
    seq:
      - id: address_to_bind
        type: byte_string
        doc: Address to bind (e.g., "0.0.0.0")
      - id: port_to_bind
        type: u4
        doc: Port number to bind
  ssh_msg_request_success:
    doc-ref: RFC 4254 section 4
    seq:
      - id: data
        size-eos: true
  global_request_response:
    doc-ref: RFC 4254 section 4
    params:
      - id: request_type
        type: u1
        enum: global_request_type
    seq:
      - id: global_request_response_fields
        type:
          switch-on: request_type
          cases:
            'global_request_type::tcpip_forward': global_request_response_tcpip_forward
            _: global_request_response_empty
  global_request_response_tcpip_forward:
    doc-ref: RFC 4254 section 7.1
    seq:
      - id: bound_port
        type: u4
  global_request_response_empty:
    doc: This is the generic empty response
  ssh_msg_request_failure:
    doc-ref: RFC 4254 section 4
  ssh_msg_userauth_info_request:
    doc-ref: RFC 4256 section 3.2
    seq:
      - id: name
        type: byte_string
      - id: instruction
        type: byte_string
      - id: language_tag
        type: byte_string
      - id: num_prompts
        type: u4
      - id: prompts
        type: prompt
        repeat: expr
        repeat-expr: num_prompts
    types:
      prompt:
        seq:
          - id: prompt
            type: byte_string
          - id: echo
            type: u1
  ssh_msg_userauth_info_response:
    doc-ref: RFC 4256 section 3.4
    seq:
      - id: num_responses
        type: u4
      - id: responses
        type: byte_string
        repeat: expr
        repeat-expr: num_responses
  ssh_msg_channel_open:
    doc-ref: RFC 4254 section 5.1
    seq:
      - id: channel_type_length
        type: u4
      - id: channel_type
        type: str
        size: channel_type_length
        encoding: ASCII
      - id: sender_channel
        type: u4
      - id: initial_window_size
        type: u4
      - id: maximum_packet_size
        type: u4
      - id: channel_specific_data
        type:
          switch-on: channel_type
          cases:
            '"session"': channel_open_session
            '"x11"': channel_open_x11
            '"forwarded-tcpip"': channel_open_forwarded_tcpip
            '"direct-tcpip"': channel_open_direct_tcpip
            #'"tun@openssh.com"': channel_open_tun_openssh # TODO
            #'"direct-streamlocal@openssh.com"': channel_open_direct_streamlocal_openssh # TODO
            #'"forwarded-streamlocal@openssh.com"': channel_open_forwarded_streamlocal_openssh # TODO
            _: invalid_message
  channel_open_session:
    doc: Clients SHOULD reject this message from a server.
    doc-ref: RFC 4254 section 6.1
  channel_open_x11:
    doc: |
      The recipient should respond with a SSH_MSG_CHANNEL_OPEN_CONFIRMATION
      or SSH_MSG_CHANNEL_OPEN_FAILURE.
    doc-ref: RFC 4254 section 6.3.2
    seq:
      - id: originator_address
        doc: IP address (e.g., "192.168.7.38")
        type: byte_string
      - id: originator_port
        type: u4
  channel_open_forwarded_tcpip:
    doc: |
      Implementations MUST reject these messages unless they previously
      requested a remove TCP/IP port forwarding with the given port number.
    doc-ref: RFC 4254 section 7.2
    seq:
      - id: connected_address
        doc: Address that was connected
        type: byte_string
      - id: connected_port
        doc: Port that was connected
        type: u4
      - id: originator_address
        doc: Originator IP address
        type: byte_string
      - id: originator_port
        doc: Originator port
        type: u4
  channel_open_direct_tcpip:
    doc: |
      When a connection comes to a locally forwarded TCP/IP port, the
      following packet is sent to the other side. Note that these messages
      MAY also be sent for ports for which no forwarding has been explicitly
      requested. The receiving side must decide whether to allow the
      forwarding.
    doc-ref: RFC 4254 section 7.2
    seq:
      - id: host_to_connect
        doc: Host to connect
        type: byte_string
      - id: port_to_connect
        doc: Port to connect
        type: u4
      - id: originator_address
        doc: Originator IP address
        type: byte_string
      - id: originator_port
        doc: Originator port
        type: u4
  ssh_msg_channel_open_confirmation:
    doc: |
      The recipient channel is the channel number given in the original
      open request, the sender channel is the channel number allocated
      by the other side.
    seq:
      - id: recipient_channel
        type: u4
      - id: sender_channel
        type: u4
      - id: initial_window_size
        type: u4
      - id: maximum_packet_size
        type: u4
  ssh_msg_channel_open_failure:
    doc: |
      If the recipent of the SSH_MSG_CHANNEL_OPEN message does not
      support the specified 'channel type,' it simply responds with
      SSH_MSG_CHANNEL_OPEN_FAILURE. The client MAY show the 'description'
      string to the user. If this is done, the client software should take
      the precautions discussed in SSH-ARCH.
    doc-ref: RFC 4254 section 5.1
    seq:
      - id: recipient_channel
        type: u4
      - id: reason_code
        type: u4
      - id: description
        type: byte_string
      - id: language_tag
        type: byte_string
  ssh_msg_channel_window_adjust:
    doc-ref: RFC 4254 section 5.2
    seq:
      - id: recipient_channel
        type: u4
      - id: bytes_to_add
        type: u4
  ssh_msg_channel_data:
    doc-ref: RFC 4254 section 5.2
    seq:
      - id: recipient_channel
        type: u4
      - id: data
        type: byte_string
  ssh_msg_channel_extended_data:
    doc-ref: RFC 4254 section 5.2
    seq:
      - id: recipient_channel
        type: u4
      - id: data_type_code
        type: u4
      - id: data
        type: byte_string
  ssh_msg_channel_eof:
    doc-ref: RFC 4254 section 5.3
    seq:
      - id: recipient_channel
        type: u4
  ssh_msg_channel_close:
    doc-ref: RFC 4254 section 5.3
    seq:
      - id: recipient_channel
        type: u4
  ssh_msg_channel_request:
    doc-ref: RFC 4254 section 5.4
    seq:
      - id: recipient_channel
        type: u4
      - id: request_type_length
        type: u4
      - id: request_type
        type: str
        size: request_type_length
        encoding: ASCII
      - id: want_reply
        type: u1
      - id: request_specific_fields
        type:
          switch-on: request_type
          cases:
            '"pty-req"': channel_request_pty_req
            '"x11-req"': channel_request_x11_req
            '"x11"': channel_request_x11
            '"env"': channel_request_env
            '"shell"': channel_request_shell
            '"exec"': channel_request_exec
            '"subsystem"': channel_request_subsystem
            '"window-change"': channel_request_window_change
            '"xon-xoff"': channel_request_xon_xoff
            '"signal"': channel_request_signal
            '"exit-status"': channel_request_exit_status
            '"exit-signal"': channel_request_exit_signal
            _: invalid_message
  channel_request_pty_req:
    doc-ref: RFC 4254 section 6.2
    seq:
      - id: term
        type: byte_string
        doc: TERM environment variable value (e.g., vt100)
      - id: terminal_width
        type: u4
        doc: terminal width, characters (e.g., 80)
      - id: terminal_height
        type: u4
        doc: terminal height, rows (e.g., 24)
      - id: terminal_width_pixels
        type: u4
        doc: terminal width, pixels (e.g., 640)
      - id: terminal_height_pixels
        type: u4
        doc: terminal height, pixels (e.g., 480)
      - id: terminal_modes
        type: byte_string
        doc: encoded terminal modes
  channel_request_x11_req:
    doc-ref: RFC 4254 section 6.3.1
    seq:
      - id: single_connection
        type: u1
      - id: x11_auth_protocol
        type: byte_string
        doc: X11 authentication protocol (e.g., "MIT-MAGIC-COOKIE-1")
      - id: x11_auth_cookie
        type: byte_string
        doc: X11 authentication cookie; hex-encoded
      - id: x11_screen_number
        type: u4
        doc: X11 screen number
  channel_request_x11:
    doc-ref: RFC 4254 section 6.3.2
    seq:
      - id: originator_address
        type: byte_string
        doc: Originator address (e.g., "192.168.7.38")
      - id: originator_port
        type: u4
  channel_request_env:
    doc-ref: RFC 4254 section 6.4
    seq:
      - id: variable_name
        type: byte_string
      - id: variable_value
        type: byte_string
  channel_request_shell:
    doc-ref: RFC 4254 section 6.5
  channel_request_exec:
    doc-ref: RFC 4254 section 6.5
    seq:
      - id: command
        type: byte_string
  channel_request_subsystem:
    doc-ref: RFC 4254 section 6.5
    seq:
      - id: subsystem_name
        type: byte_string
  channel_request_window_change:
    doc-ref: RFC 4254 section 6.7
    seq:
      - id: terminal_width
        type: u4
        doc: terminal width, columns (e.g., "80")
      - id: terminal_height
        type: u4
        doc: terminal height, rows (e.g., "24")
      - id: terminal_width_pixels
        type: u4
        doc: terminal width, pixels (e.g., "640")
      - id: terminal_height_pixels
        type: u4
        doc: terminal height, pixels (e.g., "480")
  channel_request_xon_xoff:
    doc-ref: RFC 4254 section 6.8
    seq:
      - id: client_can_do
        type: u1
  channel_request_signal:
    doc-ref: RFC 4254 section 6.9
    seq:
      - id: signal_name
        type: byte_string
        doc: Signal name (without the "SIG" prefix)
  channel_request_exit_status:
    doc-ref: RFC 4254 section 6.10
    seq:
      - id: exit_status
        type: u4
  channel_request_exit_signal:
    doc-ref: RFC 4254 section 6.10
    seq:
      - id: signal_name
        type: byte_string
        doc: Signal name (without the "SIG" prefix)
      - id: core_dumped
        type: u1
      - id: error_message
        type: utf8string
        doc: error message in UTF-8 encoding
      - id: language_tag
        type: byte_string
        doc: language tag in RFC 3066 format
  ssh_msg_channel_success:
    doc-ref: RFC 4254 section 5.4
    seq:
      - id: recipient_channel
        type: u4
  ssh_msg_channel_failure:
    doc-ref: RFC 4254 section 5.4
    seq:
      - id: recipient_channel
        type: u4

enums:
  message_type: # https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-1
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
    30: ssh_msg_kex_method_specific_30
    31: ssh_msg_kex_method_specific_31
    32: ssh_msg_kex_method_specific_32
    33: ssh_msg_kex_method_specific_33
    34: ssh_msg_kex_method_specific_34
    35: ssh_msg_kex_method_specific_35
    36: ssh_msg_kex_method_specific_36
    37: ssh_msg_kex_method_specific_37
    38: ssh_msg_kex_method_specific_38
    39: ssh_msg_kex_method_specific_39
    40: ssh_msg_kex_method_specific_40
    41: ssh_msg_kex_method_specific_41
    42: ssh_msg_kex_method_specific_42
    43: ssh_msg_kex_method_specific_43
    44: ssh_msg_kex_method_specific_44
    45: ssh_msg_kex_method_specific_45
    46: ssh_msg_kex_method_specific_46
    47: ssh_msg_kex_method_specific_47
    48: ssh_msg_kex_method_specific_48
    49: ssh_msg_kex_method_specific_49
    # Types after here should not appear in unencrypted messages.
    50: ssh_msg_userauth_request
    51: ssh_msg_userauth_failure
    52: ssh_msg_userauth_success
    53: ssh_msg_userauth_banner
    60: ssh_msg_userauth_method_specific_60
    61: ssh_msg_userauth_method_specific_61
    62: ssh_msg_userauth_method_specific_62
    63: ssh_msg_userauth_method_specific_63
    64: ssh_msg_userauth_method_specific_64
    65: ssh_msg_userauth_method_specific_65
    66: ssh_msg_userauth_method_specific_66
    67: ssh_msg_userauth_method_specific_67
    68: ssh_msg_userauth_method_specific_68
    69: ssh_msg_userauth_method_specific_69
    70: ssh_msg_userauth_method_specific_70
    71: ssh_msg_userauth_method_specific_71
    72: ssh_msg_userauth_method_specific_72
    73: ssh_msg_userauth_method_specific_73
    74: ssh_msg_userauth_method_specific_74
    75: ssh_msg_userauth_method_specific_75
    76: ssh_msg_userauth_method_specific_76
    77: ssh_msg_userauth_method_specific_77
    78: ssh_msg_userauth_method_specific_78
    79: ssh_msg_userauth_method_specific_79
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
  global_request_type:
    0: empty_response
    1: tcpip_forward
  kex_dh:
    30: ssh_msg_kexdh_init
    31: ssh_msg_kexdh_reply
  kex_dh_gex:
    30: ssh_msg_kex_dh_gex_request_old
    34: ssh_msg_kex_dh_gex_request
    31: ssh_msg_kex_dh_gex_group
    32: ssh_msg_kex_dh_gex_init
    33: ssh_msg_kex_dh_gex_reply
  kex_rsa:
    30: ssh_msg_kexrsa_pubkey
    31: ssh_msg_kexrsa_secret
    32: ssh_msg_kexrsa_done
  kex_ecdh:
    30: ssh_msg_kex_ecdh_init
    31: ssh_msg_kex_ecdh_reply
  kex_ecmqv:
    30: ssh_msg_kex_ecmqv_init
    31: ssh_msg_kex_ecmqv_reply
  kex_gssapi:
    30: ssh_msg_kexgss_init
    31: ssh_msg_kexgss_continue
    32: ssh_msg_kexgss_complete
    33: ssh_msg_kexgss_hostkey
    34: ssh_msg_kexgss_error
    40: ssh_msg_kexgss_groupreq
    41: ssh_msg_kexgss_group
  message_userauth_publickey:
    60: ssh_msg_userauth_pk_ok
  message_userauth_password:
    60: ssh_msg_userauth_passwd_changereq
  message_userauth_keyboard_interactive:
    60: ssh_msg_userauth_info_request
    61: ssh_msg_userauth_info_response
  message_userauth_gssapi_with_mic:
    60: ssh_msg_userauth_gssapi_response
    61: ssh_msg_userauth_gssapi_token
    63: ssh_msg_userauth_gssapi_exchange_complete
    64: ssh_msg_userauth_gssapi_error
    65: ssh_msg_userauth_gssapi_errtok
    66: ssh_msg_userauth_gssapi_mic
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
