meta:
  id: name_list
  title: SSH name-list
  endian: be
  xref:
    rfc: 4251
  license: CC0-1.0
doc: |
  The Secure Shell Protocol defines a "name-list" which is a list of
  comma-separated names. For expediency they are represented as
  individual values in Kaitai.
doc-ref: 'https://tools.ietf.org/html/rfc4251#section-5'
seq:
  - id: len
    type: u4
  - id: entries
    type: name_entry
    size: len
types:
  name_entry:
    doc: 'An individual entry in a `name_list`.'
    doc-ref: 'https://tools.ietf.org/html/rfc4251#section-5'
    seq:
      - id: data
        type: str
        terminator: 0x2C
        encoding: ascii
        eos-error: false
        repeat: eos
