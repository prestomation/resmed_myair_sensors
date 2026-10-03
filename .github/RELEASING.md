# Releasing ResMed myAir

Release Please runs on pushes to `main` and opens or updates a release pull
request from Conventional Commit messages. Review and merge that pull request
to create the release tag and GitHub release. The initial Release Please
baseline is `0.2.7`, matching the latest existing stable tag, `v0.2.7`.

The release pull request updates `custom_components/resmed_myair/manifest.json`
and `const.py` with the unprefixed semantic version, such as `0.2.8`; the Git
tag and GitHub release use `v0.2.8`.

When Release Please creates a release, a dependent job checks out the emitted
tag, builds `resmed_myair.zip` from that tagged component directory, validates
its contents against the unprefixed version, and uploads it to the release.
The archive therefore comes from the commit identified by the release tag.

If archive validation or upload fails after the release is created, rerun the
failed `release-asset` job from that workflow run. Upload uses `--clobber`, so
repeating a successful upload is safe. Do not move the tag to repair an
artifact; publish a follow-up release for source corrections.
