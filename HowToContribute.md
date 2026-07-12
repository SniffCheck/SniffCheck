# How to contribute

SniffCheck is a one-maintainer project that accepts contributions. This
page is the whole process — follow it and your PR can go from idea to
merged without waiting on back-and-forth.

## Before you write any code

1. Check the open issues and open pull requests first. If someone has
   already claimed the thing you want to do, pick something else or offer
   to help on their thread. Do not start parallel work on a claimed item.
2. Open an issue (or comment on an existing one) saying what you want to
   do and roughly how, and wait for a go-ahead from the maintainer before
   writing code.
3. Exception: small fixes — typos, doc corrections, obvious one-liners —
   can go straight to a PR.

## Branches and pull requests

- Fork the repo and always branch from the latest `main`. Never commit to
  `main` directly.
- One topic per branch. Name it after the change, short and descriptive:
  `fix-flasher-erase-order`, `docs-x4-pinout`.
- Keep PRs small and focused. If a change grows into two concerns, split
  it into two PRs.
- Rebase on `main` before opening the PR so it merges clean.
- The maintainer does all merges and releases. Do not merge anything
  yourself, even with an approving review.

Every PR description must include:

- **What changed and why** — a few sentences.
- **How I tested** — exactly what you ran, on what hardware or
  environment, and what you observed. "It should work" is not a test.
- **AI disclosure** — see below.

## AI-assisted contributions

AI tools are welcome here; the maintainer uses them too and says so in the
README. Two rules:

1. Disclose it. Name the tool in the PR description.
2. The AI's claims are not test results. You must personally build, run,
   and observe the change before opening the PR, and the "How I tested"
   section describes what *you* did, not what the model reported.

If an AI agent is drafting your code, point it at this file and the README
first so it works the same way you are expected to.

## Setting up to work on the web flasher

The flasher is static files at the repo root (`index.html`, `flash.js`,
`esptool/`, `firmware/`). No build step.

1. Clone the repo and serve it locally:
   `python3 -m http.server 8000`
2. Open http://localhost:8000 in Chrome or Edge. Web Serial does not exist
   in Firefox and only works on `localhost` or `https` pages.
3. Test against real hardware: a LilyGO T-Dongle C5 for the SniffCheck
   targets, or an Xteink X4 (ESP32-C3) for the Dog Park target. Flasher
   changes must be exercised on a real board before the PR goes up —
   this code erases people's devices.

## Setting up to work on the firmware

1. Install ESP-IDF v5.5.0 exactly. Other versions are not supported and
   version drift is a common source of phantom bugs.
2. Build and flash (same as the README "Build it yourself" section):

   ```
   . $IDF_PATH/export.sh
   idf.py set-target esp32c5
   idf.py build
   idf.py -p PORT flash monitor
   ```

3. The vendor database lives in its own flash partition and is not part
   of the app build. Flash it once per board:

   ```
   esptool.py -p PORT write_flash 0x310000 data/eui.bin
   ```

4. Firmware PRs must state that the branch builds clean on IDF v5.5.0 and
   was run on a real board, with a note on what you exercised.

5. Add pictures if relevant.

## Code style

Match the surrounding code — its naming, comment density, and structure.
Do not reformat files you are not otherwise changing, and do not add
sweeping refactors to a PR that is about something else.

## License

Contributions are accepted under the repo's Apache-2.0 license. By opening
a PR you agree your work is submitted under those terms.
