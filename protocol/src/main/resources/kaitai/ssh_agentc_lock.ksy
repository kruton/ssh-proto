meta:
  id: ssh_agentc_lock
  title: SSH agent lock or unlock
  endian: be
  imports:
  - byte_string
seq:
  - id: passphrase
    type: byte_string
