# Contributing

Thanks for wanting to help. Bug reports, fixes and new features are all welcome.
There is no contributor agreement to sign: under section 5 of the Apache Licence
2.0, anything you submit for inclusion is covered by the project's own licence.

What netNIMA will do, and in which order, is in [docs/PLAN.md](docs/PLAN.md).

## Reporting a bug

Open an issue and include your OS and its version, the netNIMA version (it is in
the status bar), what you connect to (a device, a program, or netNIMA's own other
end), the protocol and whether it is plain or secure, what you did, what you
expected and what happened instead.

## Building it

You need:

- [Rust](https://rustup.rs), stable
- [Node.js](https://nodejs.org), the LTS version
- What Tauri needs on your OS, listed at
  [tauri.app/start/prerequisites](https://tauri.app/start/prerequisites/):
  - Windows: Visual Studio Build Tools with "Desktop development with C++".
    WebView2 is already part of Windows 10 and 11
  - macOS: Xcode's command line tools (`xcode-select --install`)
  - Linux (Debian, Ubuntu):

    ```bash
    sudo apt install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev build-essential file
    ```

- Perl, for the OpenSSL that is built into netNIMA, for old and small
  devices. macOS and Linux have it. On Windows, use Strawberry Perl, for
  example with `scoop install perl`: the Perl that comes with Git lacks the
  modules OpenSSL's build needs. NASM is not needed: without it, OpenSSL's
  C code is used. The first build takes a while, as OpenSSL is compiled
  file by file.

Then, in the project folder:

```bash
npm install
npm run tauri dev
```

The first build takes a few minutes. After that, a change to the UI shows up at
once, and a change to the Rust code rebuilds and restarts the app.

To make the installers for your OS, with the helper inside them:

```bash
npm run package
```

They end up in `target/release/bundle/`. `npm run package` builds
`netnima-helper` first and puts it in `src-tauri/binaries/`, where the
installers take it from. `npm run tauri build` makes the app without the helper.

Two things that are easy to trip over:

- `target/release/netNIMA` only changes when you run `npm run package` again.
  After pulling new code, build again before running it.
- `target/debug/netNIMA` loads its UI from the dev server, so it only works
  while `npm run tauri dev` runs. Started on its own, its window stays empty.

The app looks for the helper beside itself. In a dev build, that is
`target/debug`, so build it there once with `cargo build -p netnima-helper`.

## Layout

```
crates/netnima-core/     everything without UI: sockets, protocols, config, decoders
crates/netnima-helper/   the only part that will need rights: low ports, capture
src-tauri/               the app: connects netnima-core and the helper to the UI
ui/                      the UI: Svelte and TypeScript, started from terNIMA's
scripts/                 builds the helper for the installers
docs/                    the plan
```

Code that does not need the window goes into `netnima-core`, with tests, so it
can be tested without starting the app.

## Making a change

1. Add or update a test in `netnima-core` that fails before your change and passes
   after it. If a change cannot be covered by a test, say why in the pull request.
2. Run the same checks CI runs:

   ```bash
   npm run check
   npm test
   npm run build
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```

3. Add a line about your change under "Unreleased" in [CHANGELOG.md](CHANGELOG.md).

## What CI checks

Every pull request runs on Windows, macOS and Linux, and all three must be green:
the UI type check, tests and build, `cargo fmt`, `cargo clippy` with warnings as
errors, the tests, and the helper run once.

## Questions

Open an issue, or reach me at nima.askari@gmail.com.
