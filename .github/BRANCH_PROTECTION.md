# Branch Protection

Branch protection is configured in GitHub repository settings, not by files in
this repository.

Recommended settings for `main`:

- Require a pull request before merging.
- Require status checks to pass before merging.
- Required status check: `test`.
- Require branches to be up to date before merging.
- Require conversation resolution before merging.
- Restrict force pushes.
- Restrict deletions.

Release tags should use the `v*` pattern. Pushing a tag such as `v0.2.0` triggers
the release workflow, which builds distributions and creates GitHub release notes.
