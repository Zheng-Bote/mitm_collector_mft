# MFT Collector

The **MFT Collector** is an autonomous Go program designed to run as a scheduled job. It connects to a remote SFTP server, downloads and parses files (e.g. CSV), encrypts the data using Envelope Encryption (AES-GCM), and inserts the raw fragments into the central MitM database's `raw_ingestion` table.

---

## 🏗️ How It Works

1.  **Bootstrapping**: Expects the MitM database connection configuration passed via `MITM_DB_*` environment variables, or via the `SCHEDULER_SOCKET_PATH` IPC mechanism.
2.  **Envelope Decryption**:
    - Reads the Key Encryption Key (KEK) from the `MASTER_KEY` environment variable.
    - Retrieves the encrypted source MFT credentials from the MitM database.
    - Decrypts the DEK using the KEK, then decrypts the MFT configuration using the DEK.
3.  **Data Extraction**:
    - Connects via SSH/SFTP to the target server.
    - Reads the `remote_dir` and processes files based on a cursor (last modified timestamp).
    - Parses the files (e.g. CSV to map).
4.  **Ingestion**:
    - Encrypts each record as a JSON fragment via AES-GCM using the DEK and a fresh random nonce.
    - Generates a deterministic `correlation_id` (UUIDv5) based on the specified `business_key_column`.
    - Inserts the encrypted records into `raw_ingestion` with `pending` status.
    - Updates the cursor offset to the file's modification time.
5.  **IPC Event Reporting**: Sends startup status, audit events, and processing progress back to the scheduler over a Unix Domain Socket.

---

## ⚙️ Configuration & Environment

### Source MFT Config Payload (Decrypted by DEK)

When configuring the MFT source in the Admin UI, the `config_payload` should look like this:

```json
{
  "host": "sftp.example.com",
  "port": 22,
  "username": "mftuser",
  "password": "mypassword",
  "private_key": "",
  "remote_dir": "/inbox",
  "archive_dir": "/archive"
}
```

### JSON CLI Arguments (`os.Args[1]`)

Example:

```json
{
  "source_name": "MFT_EMPLOYEE",
  "topic": "Employee",
  "business_key_column": "employee_id"
}
```

---

## 🛠️ Build Instructions

To compile the collector into a standalone executable, navigate to the collector directory and build:

```bash
go build -o bin/mitm-collector-mft main.go
```
