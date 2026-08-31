# Publishing

1. Bump `version` in `package.json`
2. Update `CHANGELOG.md` with the new version's changes
3. Commit: `git commit -m "Bump to vX.Y.Z"`
3. Push to `main`
4. Create a GitHub release: `gh release create vX.Y.Z --title "vX.Y.Z" --generate-notes`

The `publish.yml` workflow runs on release and publishes to npm with provenance.

Alternatively, manually dispatch `publish.yml` on `main` (Actions → Publish to
npm → Run workflow): it creates the `vX.Y.Z` release itself from the version in
`package.json`, then publishes.
