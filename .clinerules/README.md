# Cline Rules — LiteP2P

This directory contains **project rules** for the Cline agent. Cline loads every
`.md` file here on every task in this repository, in alphabetical order (use
numeric prefixes like `01-`, `02-` to control priority).

## How to use

1. **Edit `01-project-rules.md`** — it's the pre-filled starter with the
   project's layout, build commands, and conventions. Adjust anything that
   doesn't match how you want the agent to work.
2. **Add more rule files** as needed, e.g.:
   - `02-testing.md` — how/when to run tests and CI
   - `03-style.md` — coding style, naming, commit-message format
   - `04-git-workflow.md` — branching, force-push, PR etiquette
   - `05-security.md` — crypto/security handling rules (important here!)
3. **File-scoped rules**: a rule file named `filename.md` applies only when the
   agent edits/reads that path (e.g. `litep2p-core/src/main/cpp/CMakeLists.txt.md`).
   Prefix a rule with `# Context: <path>` inside a shared file to scope it.

## Format notes

- Plain Markdown. Start each file with a `#` title.
- Keep rules imperative and specific: "Always X", "Never Y", "Run Z before ...".
- Short files are better — the agent reads them on every task, so be terse.
- Rules are instructions, not documentation; put long context in `docs/` and
  reference it from a rule.
