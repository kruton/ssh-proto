meta:
  id: ssh_krl
  endian: be
  imports:
    - byte_string
    - mpint
doc-ref: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.krl
seq:
  - id: magic
    contents: [0x53, 0x53, 0x48, 0x4b, 0x52, 0x4c, 0x0a, 0x00]
  - id: format_version
    type: u4
    valid: 1
  - id: krl_version
    type: u8
  - id: generated_date
    type: u8
  - id: flags
    type: u8
    valid: 0
  - id: reserved
    type: byte_string
  - id: comment
    type: byte_string
  - id: sections
    type: section
    repeat: eos
types:
  section:
    seq:
      - id: kind
        type: u1
      - id: len
        type: u4
        valid:
          expr: _ <= _io.size - _io.pos
      - id: body
        size: len
        type:
          switch-on: kind
          cases:
            1: certificates
            2: strings
            3: strings
            5: strings
            255: extension
  strings:
    seq:
      - id: values
        type: byte_string
        repeat: eos
  certificates:
    seq:
      - id: ca_key
        type: byte_string
      - id: reserved
        type: byte_string
      - id: sections
        type: certificate_section
        repeat: eos
  certificate_section:
    seq:
      - id: kind
        type: u1
      - id: len
        type: u4
        valid:
          expr: _ <= _io.size - _io.pos
      - id: body
        size: len
        type:
          switch-on: kind
          cases:
            0x20: serial_list
            0x21: serial_range
            0x22: serial_bitmap
            0x23: strings
            0x39: extension
  serial_list:
    seq:
      - id: values
        type: u8
        repeat: eos
  serial_range:
    seq:
      - id: first
        type: u8
      - id: last
        type: u8
  serial_bitmap:
    seq:
      - id: offset
        type: u8
      - id: bitmap
        type: mpint
  extension:
    seq:
      - id: name
        type: byte_string
      - id: critical
        type: u1
        valid:
          any-of: [0, 1]
      - id: contents
        type: byte_string
