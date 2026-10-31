# cli/

**Owner:** Person B.

The single integration seam. It calls each producer's `run()`-style entry, collects the records, and passes them to the engine. This is the only place where producers and engine connect.

It lives on B's side so there is no shared orchestration file. Person A changes producer entries only through the contract in `common/`, never by editing this dir.

Entry file name and CLI flags: `[TODO: confirm at kickoff]`

Do not edit this dir if you don't own it.
