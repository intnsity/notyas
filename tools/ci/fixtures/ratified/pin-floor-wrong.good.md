# Screen specification (specimen)

The same specification, agreeing with the ratified answer. A document may state the floor;
that is what a specification is for. It may not state a different one.

## S-04 PIN entry

- Submit disabled reason: the floor the store was formatted with, as a format string over
  `LockInfo::min_pin_len`. The screen never carries the number as a literal.
- Below the device floor: Unlock disabled, with the reason beside it.

The entry surface accepts full alphanumeric (OPEN-QUESTIONS Q4, ratified: minimum 4
characters, no maximum below 64 characters).
