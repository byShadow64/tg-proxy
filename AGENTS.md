# TG Proxy contributor instructions

Repository: `byShadow64/tg-proxy`. This is a standalone source repository; preserve
the original authors' copyright, license notices and source attribution.

Read `docs/PROJECT_STATE.md`, `docs/GITHUB_CONTENT_POLICY.md`, `docs/PUBLISHER.md`
and the applicable `.cursor/rules` before changing code or publishing anything.
Android also has `android/AGENTS.md` and its own build and state documents.

- Preserve unrelated changes, user profiles, keys and immutable release packages.
- Keep Staging and private test clients separate. Never publish instrumented
  fixtures or replace released bytes with a different build of the same version.
- Check the actual source revision, tests and artifact hashes. A version string,
  documentation commit, emulator or successful handshake is not a completed release.
- Use branches and reviewable PRs after the initial source import. Do not force-push,
  move tags, import old private Git history or bypass authorization/protection.
- A release uses one approved immutable bundle. GitHub and the update server receive
  the same verified Windows assets; the release workflow never rebuilds the EXE.
- Keep tokens, private keys, passwords, local settings, raw logs and private work
  records outside Git. Credentials must not appear in command arguments or logs.
- Public README/docs/notes and issue responses contain no download or release-page
  links. Source, author, license and official technical documentation links are allowed.
  Do not hide removed links behind redirects, badges, encoded text or images.
- Keep guides, changelogs and project state consistent. Record actual checks and
  limitations; never invent a passing build, physical-device test or publication.
- Settings that change access, security or the update-server destination require
  the owner's explicit instruction. A different publisher target does not change
  the update addresses of already installed clients.
