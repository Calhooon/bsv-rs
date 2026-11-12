Saved answers for `front_pages.py --offline` and `test_front_pages.py`: a small synthetic
world in which every `check` rule passes (0.8.7 the newest stable version, 0.8.6 inside a
published advisory's range, 0.9.0-beta.1 a prerelease). The tests copy it and plant one
change per rule to see it go red. Versions and ids here are invented; nothing is copied
from a live answer. The one draft advisory is planted to prove it never reaches a page.

`docsrs_answers/` is the exception: docs.rs's own answers, read by `curl` on 2026-11-11 (the
captain's ruling T3), trimmed to the part `front_pages.py` reads. `queued.status.404.txt`: the
status endpoint of a release still in the build queue (no-mistakes 0.109.42) answered HTTP 404
with this page title. `building.*`: a release in the "Currently being built" list (presk-rt
0.17.1) answered `doc_status: false` and a builds page whose newest entry is
`build-in-progress`. `failed.*`: a release whose build had failed (trylle-cli 1.3.2) answered
`doc_status: false` and a build titled `All builds failed`. `built.*`: bsv-rs 0.8.6. The
`builds.json` endpoint answered 404 for every release asked, this crate's included; it is not
read.
