See AGENTS.md.

# Extracted plugin packages

All adapter plugins extracted out of this monorepo (omp_hub_client, fah_hub_client, any future ones) live in `codebase/` — gitignored clones of their external repos.

- Extract a plugin → clone its repo into `codebase/<repo>`.
- All work on an extracted plugin (build, test, gates, commits, publish pipeline) happens in `codebase/<repo>`, never in the monorepo.
