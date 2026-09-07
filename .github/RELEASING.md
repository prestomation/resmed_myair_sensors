# Releasing resmed_myair

## Stable releases

1. Merge release-ready changes into the default branch. Create and publish a
   GitHub Release with an unused valid `v`-prefixed stable tag targeting that
   branch. The new tag and default branch must initially name the same commit.
2. Publishing the release starts the **Release** workflow. It validates the
   event metadata and source, creates one deterministic commit that changes
   only `manifest.json` and `const.py`, and builds `resmed_myair.zip` from it.
3. The candidate is published to a unique temporary branch. The workflow
   dispatches its immutable SHA to HACS, Hassfest, locked pytest, uv-lock, and
   linter checks. The pytest dispatch is read-only and never publishes coverage.
4. Once those checks pass, the workflow atomically advances the default branch
   and replaces the release tag with an annotated tag for the validated commit.
   It rechecks both refs and uploads the verified archive. The temporary branch
   is deleted only after success.

No personal access token is required. The workflow uses `GITHUB_TOKEN`; branch
protection remains active for the stable promotion.

## Prereleases

Publish a GitHub Release with an explicit unused prerelease tag that already
matches the version in `manifest.json` and `const.py`. The workflow only builds
and uploads the archive; it does not create a commit or mutate a ref. Before
upload, the default branch and tag must still resolve to the exact selected
source.

## Failures and retries

A failed stable validation retains its temporary `release-validation/...`
branch. Verify its exact SHA before deleting it with ordinary repository access.
Do not promote that commit directly or force-move the tag.

If the final upload fails after promotion, rerun the workflow only when the
default branch and annotated tag still name the same one-parent `Release <tag>`
commit and its only changed paths are the two version files. The workflow
reproduces the version transform from the parent before resuming. Otherwise,
create a new release from current default-branch state.
