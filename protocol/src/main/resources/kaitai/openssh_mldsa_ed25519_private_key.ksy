meta:
  id: openssh_mldsa_ed25519_private_key
  endian: be
doc: OpenSSH ML-DSA-44/Ed25519 private key fields, following the key type string.
doc-ref: https://github.com/openssh/openssh-portable/blob/V_10_6_P1/ssh-mldsa-eddsa.c
seq:
- id: len_public_key
  type: u4
  valid: 1344
- id: public_key
  size: len_public_key
- id: len_private_key
  type: u4
  valid: 64
- id: private_key
  size: len_private_key
