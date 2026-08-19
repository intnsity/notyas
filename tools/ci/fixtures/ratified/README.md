# check-ratified fixtures

Every file here is a specimen for one detector in `tools/ci/check-ratified.sh`, and none
of it is compiled, linked or shipped. `tools/ci/` is not a crate; these carry `.rs` and
`.defaults` extensions only so a reader sees them in the shape the real defect had.

Two files per detector, and both halves matter:

- `*.bad.*` is the violation, written the way it actually appeared or plausibly would.
  The gate refuses to run its assertions unless the detector catches it. A detector that
  matches nothing looks exactly like a clean tree, which is how a gate goes quietly dead.
- `*.good.*` is the sanctioned form of the same code. The gate refuses to run if the
  detector fires on it. A gate that flags correct code teaches people to ignore it, and
  an ignored gate is worse than an absent one because it still reports green.

`check-ratified.sh` excludes this directory from every scan of the tree, for the obvious
reason: the fixtures contain the violations verbatim.

Adding a detector means adding both files. The self-test fails loudly when either is
missing rather than passing over a detector nobody has proved fires.
