# Release and merge policy

This document defines the merge and release requirements for `siem-detect`. A green CI run is required, but it is not sufficient by itself.

## Merge requirements

A pull request may be merged only when all of the following conditions are met:

1. Required CI checks pass on the current commit.
2. The pull request explains the motivation, scope, and relevant issue or context.
3. Verification evidence is included. Use the smallest relevant test command and add a manual CLI check when behavior changes.
4. The pull request contains one logical change. Unrelated features, fixes, and refactors should be separated.
5. Security failures are resolved rather than waived.

Direct pushes to `main` are not allowed. An emergency repair for a broken `main` branch is the only exception and requires a follow-up incident review within 24 hours.

## Versioning

The project follows [Semantic Versioning](https://semver.org/):

- **Patch**: backward-compatible bug fixes and dependency maintenance.
- **Minor**: backward-compatible user-facing features.
- **Major**: incompatible public API or behavior changes.

Conventional Commit prefixes communicate release impact: `fix:` normally indicates a patch, `feat:` a minor release, and `!` or a `BREAKING CHANGE` footer a major release.

Documentation-only changes do not require a version bump unless they accompany a release or correct published package behavior.

## Release checklist

The repository currently has no automated publishing workflow. Before creating a release manually:

1. Confirm that test and security workflows pass on the exact target commit.
2. Confirm that the version in `pyproject.toml` and `src/siem_detect/__init__.py` is identical and reflects the intended release.
3. Run the test suite:

   ```bash
   python -m pip install -e ".[dev]"
   pytest -q
   ```

4. Smoke-test the installed CLI:

   ```bash
   siem-detect tests/fixtures/nginx_attack.log --output json
   ```

5. Verify the intended distribution artifact and its bundled-rule behavior before publication.
6. Prepare release notes that summarize user-visible features, fixes, dependency changes, and documentation updates.
7. Tag the verified commit as `vX.Y.Z`.

Do not create a release solely for dependency churn. Group compatible changes into a coherent release when practical.

## Hotfixes

1. Create a `hotfix/<short-description>` branch from `main`.
2. Open a focused pull request with the incident context and verification evidence.
3. Merge only after required checks pass on the current commit.
4. Create a patch release when users need the correction in a published artifact.

## Rollback

Use `git revert` through a pull request so history is preserved and CI runs against the rollback. When releases exist, use the most recent verified tag as the known-good reference.
