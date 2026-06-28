# Contributing to Trace Lens

Thanks for your interest in contributing!

## Scope

Trace Lens v0.1 is a **single-host** blue team investigation tool for Ubuntu 24.04. The current phase prioritizes:

- SQLite storage
- Generic EDR integration via webhooks
- Lightweight web views over heavy frontend frameworks

It does **not** yet cover distributed correlation, full SIEM integration, or a custom eBPF sensor stack.

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or request features.
- If reporting a bug, include: Rust version (`rustc --version`), OS/kernel version (`uname -a`), and steps to reproduce.
- For security-sensitive issues, do **not** open a public issue. Contact the maintainers directly.

### Pull Requests

1. Fork the repository and create a feature branch.
2. Ensure `cargo build` and `cargo test` pass.
3. Follow the existing code style:
   - Rust edition 2024
   - No external comments on struct/enum fields unless nontrivial
   - Use `anyhow::Result` for fallible functions
   - Module structure follows `src/{collector,storage,engine,connectors,api}/`
4. Write tests for new detection rules, process tree logic, or API endpoints.
5. Squash commits into logical units before opening the PR.

### Code Style

- Follow the conventions already in the codebase.
- No unnecessary comments — let the code speak for itself.
- Keep PRs focused on a single concern.

## Development Setup

```bash
# Install system dependencies
sudo apt install build-essential libsqlite3-dev pkg-config

# Clone and build
git clone <repo-url>
cd traces
cargo build

# Run in development mode
cargo run -- serve --listen 127.0.0.1:18084 --db-path db/trace-lens.db

# Run validations
bash scripts/validate-h1-01-curl-bash.sh
```

## Project Structure

```
src/
├── main.rs                  # Entry point
├── app.rs                   # CLI command dispatch
├── cli/                     # Clap definitions
├── model/                   # Data structs
├── collector/               # Tracee ingest, Ring0, canaries
├── storage/                 # SQLite operations
├── engine/                  # Process tree, incidents, IOC, trust
├── connectors/              # EDR adapter trait + implementations
└── api/                     # Axum HTTP server + EDR ingest
```

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
