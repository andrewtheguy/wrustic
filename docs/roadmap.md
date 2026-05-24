# Roadmap

- Read passphrase from stdin (for scripted / non-interactive use)
- Windows support (requires replacing Unix-specific `OpenOptionsExt` mode
  `0600` on `config.toml` with an ACL-based equivalent)
