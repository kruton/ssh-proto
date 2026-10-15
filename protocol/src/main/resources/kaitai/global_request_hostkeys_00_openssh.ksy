meta:
  id: global_request_hostkeys_00_openssh
  endian: be
  imports:
  - byte_string
doc-ref: openssh-PROTOCOL.txt
seq:
- id: hostkeys
  type: byte_string
  repeat: eos
  doc: Server public key blobs, each in an SSH string, including unknown key types.
