meta:
  id: ssh_agentc_add_identity
  title: SSH agent add identity
  endian: be
  imports:
  - ssh_agent_enums
  - ascii_string
  - byte_string
  - mpint
seq:
  - id: key_type
    type: ascii_string
    valid:
      expr: _.value == "ssh-rsa" or _.value == "ssh-dss" or _.value == "ecdsa-sha2-nistp256" or _.value == "ecdsa-sha2-nistp384" or _.value == "ecdsa-sha2-nistp521"
  - id: key
    type:
      switch-on: key_type.value
      cases:
        '"ssh-rsa"': rsa
        '"ssh-dss"': dsa
        '"ecdsa-sha2-nistp256"': ec
        '"ecdsa-sha2-nistp384"': ec
        '"ecdsa-sha2-nistp521"': ec
  - id: comment
    type: byte_string
  - id: constraints
    type: constraint
    repeat: eos
types:
  rsa:
    seq:
      - id: n
        type: mpint
      - id: e
        type: mpint
      - id: d
        type: mpint
      - id: iqmp
        type: mpint
      - id: p
        type: mpint
      - id: q
        type: mpint
  dsa:
    seq:
      - id: p
        type: mpint
      - id: q
        type: mpint
      - id: g
        type: mpint
      - id: y
        type: mpint
      - id: x
        type: mpint
  ec:
    seq:
      - id: curve
        type: ascii_string
      - id: point
        type: byte_string
      - id: scalar
        type: mpint
  constraint:
    seq:
      - id: kind
        type: u1
        enum: ssh_agent_enums::constraint_kind
        valid:
          any-of: [ssh_agent_enums::constraint_kind::lifetime, ssh_agent_enums::constraint_kind::confirm]
      - id: lifetime
        type: u4
        if: kind == ssh_agent_enums::constraint_kind::lifetime
