meta:
  id: ssh_mldsa_p384_public_key_blob
  endian: be
doc-ref: https://datatracker.ietf.org/doc/html/draft-ietf-sshm-composite-sigs-00
seq:
- id: len_key
  type: u4
  valid: 2693
- id: mldsa_key
  size: 2592
- id: len_q
  type: u4
  valid: 97
- id: q
  size: len_q
