# Hand-written notes of a Release page

`docs/releases/<X.Y.Z>.md` holds what a Release page says that no machine can read from the tree, the run or the published advisories. When the file exists at the tag, `front_pages.py notes` places it at the top of the page, under the kind line, above the generated entries; a page without one is the generated page alone.

- A title line `# bsv-rs X.Y.Z` (dropped from the page; the page has its own title).
- `## In short`: one bold sentence per change a user would notice, in plain words, with the advisory and the issue it closes.
- `## Not changed`: what a reader might expect to have moved and did not.
- `## How it was checked`: the runs behind the release's sentences, by what they were run on.

It lands on `beta` by its own pull request before the tag, and `main` takes it by `git cherry-pick -x` with the front pages under the direction rule's fifth class (`RELEASING.md`; the owner's word of 2026-11-12). It names no figure the page's generated block already carries, and nothing of a draft advisory.
