# S-46 golden field lists

`s46-fields.txt` is the rendered label sequence of the Verify-device screen with a
session open; `s46-fields-pre-pin.txt` is the same sequence with none.

VERIFY.md 11.7 makes both a CI assertion: the field order is FROZEN, so that two units
held side by side can be scanned rather than read, and the pre-PIN set is a strict
subset of the unlocked one (7.4). A change to either file is therefore a deliberate,
reviewed change to the screen's contract - which is the whole reason the lists are data
in a file a reviewer reads as a diff, rather than a literal buried in a test.

The labels are the ones the fixture in `src/screens/verify.rs` renders, values and all:
a hashed region carries its offset and length in its label, and the radio row names the
pad it read, so those lines carry the fixture's numbers. The fixture mirrors VERIFY.md
11.3's wireframe, so the list reads against the specification directly.
