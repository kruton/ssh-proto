meta:
  id: ssh_mldsa_signature_blob
  endian: be
params:
- id: expected_size
  type: u4
doc-ref: https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/08/
doc: Fixed-size raw ML-DSA or ML-DSA-44/Ed25519 signature in an SSH string.
seq:
- id: len_signature
  type: u4
  valid: expected_size
- id: signature
  size: len_signature
