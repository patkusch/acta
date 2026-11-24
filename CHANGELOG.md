# Changelog

All notable changes to this project are listed here, newest first.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `acta version` and `acta --version` print the version.
- A one-line-per-entry view of a ledger (`acta show`).
- `acta step` (one agent action per call into a resumable ledger) and `acta serve` (a small public checker for ledgers).

### Fixed
- Closing a ledger twice now says so plainly and exits with 2, instead of printing a stack trace.

### Changed
- Dependencies updated within their allowed ranges; TypeScript is now 5.9.

## [0.1.0] - 2026-09-02

First version. A tamper-evident record of what an agent actually did.

- An attack catalogue, a recording proxy for MCP tool calls, a command line and a demo.
- The tool list the agent was shown is recorded in the chain.
- Git notes as a place to anchor the record, then a kernel-enforced append-only file that an attacker cannot rewrite.
- Resuming a session after a restart without laundering the ledger, and key rotation within a session.
- Every call is bound to the definition the agent was shown.
- Anchoring into a public GitHub commit, and into a Sigstore Rekor transparency log entry, with a witness ledger so a rewritten witness is a finding.
- Rekor checkpoint signatures are verified, and the log is checked for consistency across submissions.
