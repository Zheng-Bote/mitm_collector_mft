# Changelog - MitM MFT Collector

## [v1.0.0] - 2026-09-19

### Added
- **MFT Collector**: Initial implementation in Go 1.26.5 to securely collect files (e.g. CSV) from remote SFTP servers.
- **Envelope Encryption**: Supports in-memory decryption of source credentials and immediate AES-GCM encryption of ingested records before they touch the database.
- **IPC Integration**: Deeply integrated with `mitm_scheduler` for real-time progress, dynamic configuration, and audit logging.
