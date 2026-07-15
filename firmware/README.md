# firmware/ — flasher assets (network-first, never stale-cached)

The Flash tab loads `manifest.json` from here and esp-web-tools writes the referenced
`.bin` to the stick. **`sniffcheck-merged.bin` is not committed to this app tree** —
it is dropped in by the release/publish step (the public-repo git is the owner's job;
see the `public-repo-hands-off` note).

To publish a build:

1. Copy the merged image to `sniffcheck-merged.bin` (offset 0), e.g. from
   `docs/webflasher/firmware/sniffcheck-merged.bin` in the private repo.
2. Bump `version` in `manifest.json` to the firmware version.

The service worker caches `/firmware/*` **network-first** (see `vite.config.ts`), so a
newly published binary is never masked by a stale cached copy.
