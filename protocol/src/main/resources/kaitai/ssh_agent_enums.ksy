meta:
  id: ssh_agent_enums
  title: SSH agent protocol constants
  license: CC0-1.0
enums:
  message_type:
    5: failure
    6: success
    11: request_identities
    12: identities_answer
    13: sign_request
    14: sign_response
    17: add_identity
    18: remove_identity
    19: remove_all_identities
    22: lock
    23: unlock
    25: add_id_constrained
    27: extension
  constraint_kind:
    1: lifetime
    2: confirm
