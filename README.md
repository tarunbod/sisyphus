# Sispyhus Password Manager

> This project is a work in progress. Many features are yet to be finished.

Sisyphus is a command-line stateless password manager. It does not store your
passwords anywhere. Instead, it derives your passwords based on a master
username and password. If this concept sounds familiar, that's because this
project is a clone of [Spectre](https://spectre.app/) (formerly known as
masterpassword).

## Installation

### Prerequisites

- Rust version 1.67 (older versions may or may not work, 1.67 is the version I
  developed with)

### Steps

1. Clone this repo.
   - `git clone https://github.com/tarunbod/sisyphus.git`
   - `cd sisyphus/cli`
2. Build and install the project with Cargo.
   - `cargo install --path .`

## Usage

The executable is called `spm`. Available commands are:
- `spm login` - Saves your master username and password to your operating
  system's native secure store. (On Windows, this is Credential Manager. On
  macOS, this is Keychain. On linux, this is keyutils. See
  [`keyring`](https://lib.rs/crates/keyring) for more info).
- `spm logout` - Removes any saved information from your secure store.
- `spm get` - Derives password for a given site name based on your saved
  credentials (can optionally specify a username and password manually with the
  `-u` flag). Optional arguments include site counter and password type (see how
  [Spectre](https://spectre.app/) works for more info).

Run `spm --help` for more help.

## Known Issues

- Saving credentials or copying to clipboard does not currently work on WSL
