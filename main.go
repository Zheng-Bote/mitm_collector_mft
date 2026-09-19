/**
 * SPDX-FileComment: MFT Collector
 * SPDX-FileType: SOURCE
 * SPDX-FileContributor: ZHENG Robert
 * SPDX-FileCopyrightText: 2026 ZHENG Robert
 * SPDX-License-Identifier: Apache-2.0
 *
 * @file main.go
 * @brief Autonomous collector retrieving data from MFT/SFTP, encrypting it, and saving it to RAW tables.
 * @version 1.0.0
 * @date 2026-09-19
 *
 * @author ZHENG Robert (robert@hase-zheng.net)
 * @copyright Copyright (c) 2026 ZHENG Robert
 * @license Apache-2.0
 */

package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	appName        = "MFT Collector"
	appDescription = "Extracts data from MFT/SFTP endpoints"
	version        = "1.0.0"
)

type TargetDBConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	Password   string `json:"password"`
	Database   string `json:"database"`
	DSN        string `json:"dsn"`
	SourceName string `json:"source_name"`
}

type MFTConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	RemoteDir  string `json:"remote_dir"`
	ArchiveDir string `json:"archive_dir"`
}

type CollectorArgs struct {
	SourceName        string `json:"source_name"`
	Topic             string `json:"topic"`
	BusinessKeyColumn string `json:"business_key_column"`
}

type StatusEvent struct {
	RunID     int    `json:"run_id"`
	Type      string `json:"type"`
	Component string `json:"component"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	Progress  int    `json:"progress"`
}

type IPCClient struct {
	SocketPath string
	RunID      int
	Component  string
	Topic      string
	SourceName string
}

func (c *IPCClient) SendEvent(status, message string, progress int) {
	if c == nil || c.SocketPath == "" {
		return
	}
	conn, err := net.Dial("unix", c.SocketPath)
	if err != nil {
		log.Printf("[IPC ERROR] Failed to connect to scheduler socket: %v", err)
		return
	}
	defer conn.Close()

	if c.Topic != "" && c.SourceName != "" {
		message = fmt.Sprintf("%s: %s: %s", c.Topic, c.SourceName, message)
	}

	event := StatusEvent{
		RunID:    c.RunID,
		Type:     "status",
		Status:   status,
		Message:  message,
		Progress: progress,
	}
	data, _ := json.Marshal(event)
	_, _ = conn.Write(append(data, '\n'))
}

func (c *IPCClient) SendAudit(message string) {
	if c == nil || c.SocketPath == "" {
		return
	}
	conn, err := net.Dial("unix", c.SocketPath)
	if err != nil {
		return
	}
	defer conn.Close()

	if c.Topic != "" && c.SourceName != "" {
		message = fmt.Sprintf("%s: %s: %s", c.Topic, c.SourceName, message)
	}

	event := StatusEvent{
		RunID:     c.RunID,
		Type:      "audit",
		Component: c.Component,
		Message:   message,
	}
	data, _ := json.Marshal(event)
	_, _ = conn.Write(append(data, '\n'))
}

func main() {
	if dbCfg, masterKey, err := fetchCredentialsFromScheduler(); err == nil {
		if dbCfg != "" {
			os.Setenv("MITM_DB_CONFIG_JSON", dbCfg)
		}
		if masterKey != "" {
			os.Setenv("MASTER_KEY", masterKey)
		}
	} else if os.Getenv("RUN_ID") != "" && os.Getenv("SCHEDULER_SOCKET_PATH") != "" {
		log.Printf("[IPC Warning] Failed to get credentials from scheduler: %v", err)
	}

	var ipc *IPCClient
	runIDStr := os.Getenv("RUN_ID")
	socketPath := os.Getenv("SCHEDULER_SOCKET_PATH")
	if runIDStr != "" && socketPath != "" {
		runID, err := strconv.Atoi(runIDStr)
		if err == nil {
			ipc = &IPCClient{
				SocketPath: socketPath,
				RunID:      runID,
				Component:  "mitm_collector_mft",
			}
		}
	}

	ipc.SendEvent("started", fmt.Sprintf("%s (%s) started", appName, version), 0)
	ipc.SendAudit(fmt.Sprintf("%s (%s) started", appName, version))

	var targetCfg TargetDBConfig
	jsonConfig := os.Getenv("MITM_DB_CONFIG_JSON")

	if jsonConfig != "" {
		var fullCfg struct {
			DB struct {
				Host     string `json:"host"`
				Port     int    `json:"port"`
				User     string `json:"user"`
				Password string `json:"password"`
				Database string `json:"database"`
				SSLMode  bool   `json:"sslmode"`
			} `json:"db"`
		}
		if err := json.Unmarshal([]byte(jsonConfig), &fullCfg); err != nil {
			log.Fatalf("Failed to parse MitM JSON configuration: %v", err)
		}
		targetCfg.Host = fullCfg.DB.Host
		targetCfg.Port = fullCfg.DB.Port
		targetCfg.User = fullCfg.DB.User
		targetCfg.Password = fullCfg.DB.Password
		targetCfg.Database = fullCfg.DB.Database
		if fullCfg.DB.SSLMode {
			os.Setenv("MITM_DB_SSLMODE", "require")
		} else {
			os.Setenv("MITM_DB_SSLMODE", "disable")
		}
	} else {
		targetCfg.Host = os.Getenv("MITM_DB_HOST")
		if portStr := os.Getenv("MITM_DB_PORT"); portStr != "" {
			targetCfg.Port, _ = strconv.Atoi(portStr)
		}
		targetCfg.User = os.Getenv("MITM_DB_USER")
		targetCfg.Password = os.Getenv("MITM_DB_PASSWORD")
		targetCfg.Database = os.Getenv("MITM_DB_NAME")
	}

	if targetCfg.Host == "" {
		log.Fatal("MitM database credentials not found in environment")
	}

	topicName := "mft.data"
	businessKeyCol := "id"

	if len(os.Args) >= 2 {
		var colArgs CollectorArgs
		if err := json.Unmarshal([]byte(os.Args[1]), &colArgs); err == nil {
			if colArgs.SourceName != "" {
				targetCfg.SourceName = colArgs.SourceName
			}
			if colArgs.Topic != "" {
				topicName = colArgs.Topic
			}
			if colArgs.BusinessKeyColumn != "" {
				businessKeyCol = colArgs.BusinessKeyColumn
			}
		}
	}

	if targetCfg.SourceName == "" {
		targetCfg.SourceName = "MFT_SOURCE"
	}

	if ipc != nil {
		ipc.Topic = topicName
		ipc.SourceName = targetCfg.SourceName
	}

	sslMode := os.Getenv("MITM_DB_SSLMODE")
	if sslMode == "true" {
		sslMode = "require"
	} else if sslMode == "false" || sslMode == "" {
		sslMode = "disable"
	}

	mitmDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		targetCfg.User, targetCfg.Password, targetCfg.Host, targetCfg.Port, targetCfg.Database, sslMode)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	configMitmPool, err := pgxpool.ParseConfig(mitmDSN)
	if err != nil {
		log.Fatalf("Failed to parse DB config: %v", err)
	}
	mitmPool, err := pgxpool.NewWithConfig(ctx, configMitmPool)
	if err != nil {
		log.Fatalf("Failed to connect to MitM database: %v", err)
	}
	defer mitmPool.Close()

	masterKey := os.Getenv("MASTER_KEY")
	kek, err := validateKEK(masterKey)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var configPayload []byte
	var credentialsNonce []byte
	var dekID string

	err = mitmPool.QueryRow(ctx, `
		SELECT config_payload, nonce, dek_id 
		FROM source_credentials 
		WHERE source_name = $1 AND is_active = true 
		LIMIT 1
	`, targetCfg.SourceName).Scan(&configPayload, &credentialsNonce, &dekID)
	if err != nil {
		log.Fatalf("Failed to load source credentials: %v", err)
	}

	var wrappedKey []byte
	err = mitmPool.QueryRow(ctx, `
		SELECT wrapped_key 
		FROM storage_keys 
		WHERE id = $1 AND is_active = true 
		LIMIT 1
	`, dekID).Scan(&wrappedKey)
	if err != nil {
		log.Fatalf("Failed to load wrapped DEK: %v", err)
	}

	dekNonce := wrappedKey[:12]
	wrappedCipher := wrappedKey[12:]

	kekBlock, err := aes.NewCipher(kek)
	kekGCM, err := cipher.NewGCM(kekBlock)
	dek, err := kekGCM.Open(nil, dekNonce, wrappedCipher, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt DEK: %v", err)
	}

	dekBlock, err := aes.NewCipher(dek)
	dekGCM, err := cipher.NewGCM(dekBlock)
	decryptedConfigBytes, err := dekGCM.Open(nil, credentialsNonce, configPayload, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt MFT config: %v", err)
	}

	var mftCfg MFTConfig
	if err := json.Unmarshal(decryptedConfigBytes, &mftCfg); err != nil {
		log.Fatalf("Failed to parse decrypted MFT configuration: %v", err)
	}

	if mftCfg.Port == 0 {
		mftCfg.Port = 22
	}

	ipc.SendEvent("processing", "Connecting to SFTP", 30)

	var authMethods []ssh.AuthMethod
	if mftCfg.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(mftCfg.PrivateKey))
		if err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	} else if mftCfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(mftCfg.Password))
	}

	sshConfig := &ssh.ClientConfig{
		User:            mftCfg.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", mftCfg.Host, mftCfg.Port), sshConfig)
	if err != nil {
		log.Fatalf("Failed to dial SSH: %v", err)
	}
	defer conn.Close()

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		log.Fatalf("Failed to start SFTP: %v", err)
	}
	defer sftpClient.Close()

	ipc.SendEvent("processing", "Connected to SFTP, starting ingestion", 50)

	var lastCursor string
	err = mitmPool.QueryRow(ctx, "SELECT last_cursor FROM ingestion_cursors WHERE source_name = $1", targetCfg.SourceName).Scan(&lastCursor)

	files, err := sftpClient.ReadDir(mftCfg.RemoteDir)
	if err != nil {
		log.Fatalf("Failed to read remote directory: %v", err)
	}

	recordsIngested := 0
	recordsFailed := 0
	var maxCursorValue string

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(strings.ToLower(file.Name()), ".csv") {
			continue
		}

		fileTime := file.ModTime().Format(time.RFC3339)
		if lastCursor != "" && fileTime <= lastCursor {
			continue
		}

		remotePath := mftCfg.RemoteDir + "/" + file.Name()
		f, err := sftpClient.Open(remotePath)
		if err != nil {
			log.Printf("Failed to open file %s: %v", remotePath, err)
			continue
		}

		reader := csv.NewReader(f)
		headers, err := reader.Read()
		if err != nil {
			f.Close()
			continue
		}

		batch := &pgx.Batch{}
		batchSize := 0

		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}

			rowMap := make(map[string]interface{})
			for i, val := range record {
				if i < len(headers) {
					rowMap[headers[i]] = val
				}
			}

			rowJSON, _ := json.Marshal(rowMap)
			nonce := make([]byte, 12)
			io.ReadFull(rand.Reader, nonce)
			encryptedPayload := dekGCM.Seal(nil, nonce, rowJSON, nil)

			businessKey := ""
			if bk, ok := rowMap[businessKeyCol]; ok {
				businessKey = fmt.Sprintf("%v", bk)
			}
			if businessKey == "" {
				businessKey = uuid.New().String()
			}

			namespaceMitM := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
			correlationID := uuid.NewSHA1(namespaceMitM, []byte(businessKey))

			batch.Queue(`
				INSERT INTO raw_ingestion (topic, source_system, correlation_id, payload, nonce, dek_id, status)
				VALUES ($1, $2, $3, $4, $5, $6, 'pending')
			`, topicName, targetCfg.SourceName, correlationID, encryptedPayload, nonce, dekID)
			batchSize++
		}
		f.Close()

		if batchSize > 0 {
			tx, _ := mitmPool.Begin(ctx)
			br := tx.SendBatch(ctx, batch)
			
			batchError := false
			for i := 0; i < batchSize; i++ {
				_, err := br.Exec()
				if err != nil {
					batchError = true
				}
			}
			br.Close()

			if batchError {
				tx.Rollback(ctx)
				recordsFailed += batchSize
			} else {
				tx.Commit(ctx)
				recordsIngested += batchSize
				if fileTime > maxCursorValue {
					maxCursorValue = fileTime
				}
				
				if mftCfg.ArchiveDir != "" {
					sftpClient.Rename(remotePath, mftCfg.ArchiveDir+"/"+file.Name())
				}
			}
		}
	}

	if recordsIngested > 0 && maxCursorValue != "" {
		mitmPool.Exec(ctx, `
			INSERT INTO ingestion_cursors (source_name, last_cursor, updated_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (source_name) 
			DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()
		`, targetCfg.SourceName, maxCursorValue)
		ipc.SendAudit(fmt.Sprintf("Ingested %d MFT records. Cursor updated to %s.", recordsIngested, maxCursorValue))
	}

	ipc.SendAudit(fmt.Sprintf("Successfully processed and ingested %d MFT records into RAW table. Failed: %d", recordsIngested, recordsFailed))
	ipc.SendAudit(fmt.Sprintf("%s (%s) finished", appName, version))
	log.Printf("Collector finished. Ingested %d records. Failed %d.", recordsIngested, recordsFailed)
}

func validateKEK(masterKey string) ([]byte, error) {
	var kek []byte
	if decoded, err := base64.StdEncoding.DecodeString(masterKey); err == nil {
		kek = decoded
	} else {
		kek = []byte(masterKey)
	}

	if len(kek) != 32 {
		return nil, fmt.Errorf("invalid MASTER_KEY length: expected 32 bytes, got %d", len(kek))
	}
	return kek, nil
}

func fetchCredentialsFromScheduler() (string, string, error) {
	runIDStr := os.Getenv("RUN_ID")
	socketPath := os.Getenv("SCHEDULER_SOCKET_PATH")
	if runIDStr == "" || socketPath == "" {
		return "", "", fmt.Errorf("not running under scheduler")
	}
	
	runID, err := strconv.Atoi(runIDStr)
	if err != nil {
		return "", "", err
	}
	
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := map[string]interface{}{
		"type":   "get_credentials",
		"run_id": runID,
	}
	data, _ := json.Marshal(req)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return "", "", err
	}

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		var resp struct {
			MasterKey    string `json:"master_key"`
			DBConfigJSON string `json:"db_config_json"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &resp); err == nil {
			return resp.DBConfigJSON, resp.MasterKey, nil
		}
	}
	return "", "", fmt.Errorf("no response or invalid JSON from scheduler")
}
