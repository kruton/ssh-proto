meta:
  id: ssh_agentc_remove_identity
  title: SSH agent remove identity
  endian: be
  imports:
  - byte_string
seq:
  - id: key_blob
    type: byte_string
