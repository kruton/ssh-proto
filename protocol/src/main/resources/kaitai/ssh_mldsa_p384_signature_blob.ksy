meta:
  id: ssh_mldsa_p384_signature_blob
  endian: be
  imports:
  - mpint
doc-ref: https://datatracker.ietf.org/doc/html/draft-ietf-sshm-composite-sigs-00
seq:
- id: len_signature
  type: u4
  valid:
    min: 4637
    max: 4733
- id: signature
  type: composite_signature
  size: len_signature
types:
  composite_signature:
    seq:
    - id: mldsa_signature
      size: 4627
    - id: r
      type: mpint
    - id: s
      type: mpint
