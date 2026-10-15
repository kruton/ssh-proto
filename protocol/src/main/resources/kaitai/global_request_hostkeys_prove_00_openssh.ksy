meta:
  id: global_request_hostkeys_prove_00_openssh
  endian: be
  imports:
  - byte_string
doc-ref: openssh-PROTOCOL.txt
seq:
- id: hostkeys
  type: byte_string
  repeat: eos
  doc: Public key blobs for which the client requests proof of private key possession.
