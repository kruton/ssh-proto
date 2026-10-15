meta:
  id: global_request_response_hostkeys_prove_00_openssh
  endian: be
  imports:
  - byte_string
doc-ref: https://www.openssh.com/txt/PROTOCOL
seq:
- id: signatures
  type: byte_string
  repeat: eos
  doc: SSH signature blobs in the same order as the requested host keys.
