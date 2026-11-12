# Install bas

You can install `bas` from a GitHub release or build it from source. Each release has an archive for Linux on x86_64, macOS on ARM64, and Windows on x86_64.

## Install from a release

Download the archive for your platform from the [releases page](https://github.com/Snestra/bas/releases), extract it, and put `bas` on your `PATH`. The archive holds `bas` (or `bas.exe` on Windows) and the README.

```sh
tar -xzf bas-Linux-X64.tar.gz
command -v bas || echo "the name bas is free"
install -d -m 0755 ~/.local/bin
install -m 0755 bas ~/.local/bin/bas
export PATH="$HOME/.local/bin:$PATH"
bas --version
```

Before you copy `bas` onto your `PATH`, check that no other program already uses the name. Run `command -v bas` on Linux and macOS, or `Get-Command bas` in PowerShell.

```text
on(install bas)
  if command -v bas finds another program
    keep bas in its own directory and call it by its full path
  else
    copy bas onto PATH
```

Release v0.4.0 includes the broker commands on Linux, and v0.5.0 adds them on macOS. The Linux archive includes `contrib/linux/` with the service unit, example settings, and shims, and the macOS archive includes `contrib/macos/` with the LaunchDaemons. Tailscale is optional for all platforms.

## Build from source

You need Rust 1.89 or newer and the native build tools for your platform. On Linux, the build also needs the OpenSSL development files and `pkg-config` (on Debian and Ubuntu, the `libssl-dev` and `pkg-config` packages). The Agent Access crates come from a pinned Git revision, so the first build needs access to the `bitwarden/agent-access` repository on GitHub and to crates.io.

```sh
git clone https://github.com/Snestra/bas
cd bas
cargo build --locked --release
./target/release/bas --version
```

On Windows, the program is `target\release\bas.exe`. Rust 1.89 is the minimum version, because grants use the file locks in the standard library.

```text
target/release/
└── bas      # one program: the CLI, the terminal UI, and on Linux the broker
```

## Next step

Sign in with a machine account access token, as [Sign in with an access token](first-run.md) shows.
