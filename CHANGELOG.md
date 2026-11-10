# Changelog - MitM MFT Collector

## [v0.1.2] - 2026-11-10

### Fixed
- All fatal errors are now sent both as `failed` status event and as audit event (`ERROR: <message>`) to the scheduler, so they appear in `job_audit_logs`.
- Unparsable collector arguments (JSON in `os.Args[1]`) now abort the run with an error instead of continuing with default values.
- Wrapped DEK length and all cipher initializations are checked; invalid key data no longer causes a panic.

## [v0.1.0] - 2026-09-19

### Added
- **MFT Collector**: Initial implementation in Go 1.26.5 to securely collect files (e.g. CSV) from remote SFTP servers.
- **Envelope Encryption**: Supports in-memory decryption of source credentials and immediate AES-GCM encryption of ingested records before they touch the database.
- **IPC Integration**: Deeply integrated with `mitm_scheduler` for real-time progress, dynamic configuration, and audit logging.
