meta:
  id: ssh_hybrid_kex_blob
  endian: be
doc: Hybrid KEX public key or reply containing fixed-width post-quantum and classical components.
params:
- id: len_pq_data
  type: u4
- id: len_classical_data
  type: u4
seq:
- id: pq_data
  size: len_pq_data
- id: classical_data
  size: len_classical_data
