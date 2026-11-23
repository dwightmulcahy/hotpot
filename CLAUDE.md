# CLAUDE.md

Instructions for AI coding agents working in this repository.

## Git workflow (applies to every change)

1. **One PR per change.** Every change goes through its own pull request and is merged only after CI passes. If CI fails, keep fixing it on the same branch until it is green.
2. **Merge order.** When several PRs are open, merge them in a deliberate order (dependencies first), rebasing each onto the updated default branch before merging.
3. **Conventional Commits.** Commit messages and PR titles use `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `build:`, `refactor:`, `chore:` … (release notes and version bumps are built from them).
4. **No direct commits to the default branch.** It only changes by merging or rebasing PRs.
