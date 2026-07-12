package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	minioClient    *minio.Client
	minioBucket    string
	minioTaskQueue = make(chan AuditLogPayload, 2000)
)

func initMinIO() {
	endpoint := os.Getenv("MINIO_ENDPOINT")
	accessKey := os.Getenv("MINIO_ACCESS_KEY")
	secretKey := os.Getenv("MINIO_SECRET_KEY")
	baseBucket := os.Getenv("MINIO_BUCKET_NAME")
	if baseBucket == "" {
		baseBucket = "compliance-audit-logs"
	}

	if GatewayConfig.MinioObjectLocking {
		minioBucket = baseBucket + "-worm"
	} else {
		minioBucket = baseBucket + "-free"
	}

	if endpoint == "" || accessKey == "" || secretKey == "" || minioBucket == "" {
		log.Println("[MinIO Warn] MinIO environmental variables not fully configured. Compliance archival is disabled.")
		return
	}

	var err error
	// Set up high-performance connection pool transport
	transport := &http.Transport{
		MaxIdleConns:        2000,
		MaxIdleConnsPerHost: 2000,
		IdleConnTimeout:     90 * time.Second,
	}

	// Set up the client connection
	minioClient, err = minio.New(endpoint, &minio.Options{
		Creds:     credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:    false,
		Transport: transport,
	})
	if err != nil {
		log.Printf("[MinIO Error] Failed to initialize MinIO client: %v", err)
		return
	}

	log.Printf("[MinIO] Connecting to datalake endpoint: %s", endpoint)

	// Verify or create the bucket with a retry loop (handles Docker network DNS propagation delays)
	var exists bool
	for attempt := 1; attempt <= 10; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		exists, err = minioClient.BucketExists(ctx, minioBucket)
		cancel()
		if err == nil {
			break
		}
		log.Printf("[MinIO Warning] Attempt %d: Failed to check if bucket exists: %v. Retrying in 2s...", attempt, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Printf("[MinIO Error] Exhausted retries. Failed to check if bucket exists: %v", err)
		return
	}

	if !exists {
		useLocking := GatewayConfig.MinioObjectLocking
		log.Printf("[MinIO] Bucket '%s' does not exist. Creating (WORM Object Locking: %t)...", minioBucket, useLocking)
		createCtx, createCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = minioClient.MakeBucket(createCtx, minioBucket, minio.MakeBucketOptions{
			ObjectLocking: useLocking,
		})
		createCancel()
		if err != nil {
			log.Printf("[MinIO Error] Failed to create bucket: %v", err)
			return
		}

		if useLocking {
			// Configure compliance WORM default retention policy (30 days)
			mode := minio.Compliance
			validity := uint(30)
			unit := minio.Days
			lockCtx, lockCancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = minioClient.SetBucketObjectLockConfig(lockCtx, minioBucket, &mode, &validity, &unit)
			lockCancel()
			if err != nil {
				log.Printf("[MinIO Error] Failed to set default compliance object lock: %v", err)
				return
			}
			log.Printf("[MinIO] Bucket '%s' configured successfully with WORM COMPLIANCE object locking (30 days retention).", minioBucket)
		} else {
			log.Printf("[MinIO] Bucket '%s' created successfully without WORM object locking.", minioBucket)
		}
	} else {
		log.Printf("[MinIO] Bucket '%s' already exists and is active.", minioBucket)
	}

	// Ensure staging, quarantine, and demo buckets exist
	extraBuckets := []string{"staging", "quarantine", "demo"}
	for _, b := range extraBuckets {
		exists, err := minioClient.BucketExists(context.Background(), b)
		if err == nil && !exists {
			log.Printf("[MinIO] Bucket '%s' does not exist. Creating...", b)
			createCtx, createCancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = minioClient.MakeBucket(createCtx, b, minio.MakeBucketOptions{})
			createCancel()
			if err != nil {
				log.Printf("[MinIO Error] Failed to create bucket '%s': %v", b, err)
			} else {
				log.Printf("[MinIO] Bucket '%s' created successfully.", b)
			}
		}
	}

	// Start the dedicated high-performance worker pool for MinIO uploads
	StartMinIOWorkerPool()
}

func StartMinIOWorkerPool() {
	// Spawn 35 dedicated compliance archival workers
	for i := 0; i < 35; i++ {
		go func() {
			for payload := range minioTaskQueue {
				uploadAuditLogSync(payload.TransactionID, payload)
			}
		}()
	}
	log.Println("[MinIO] Started dedicated WORM archiving worker pool (35 workers).")
}

type AuditLogPayload struct {
	TransactionID     string      `json:"transaction_id"`
	SessionID         string      `json:"session_id"`
	Observation       int         `json:"observation"`
	VFEScore          float64     `json:"vfe_score"`
	VFEScoreL1        float64     `json:"vfe_score_l1"`
	VFEScoreL3        float64     `json:"vfe_score_l3"`
	IsBlocked         bool        `json:"is_blocked"`
	Timestamp         time.Time   `json:"timestamp"`
	ClientIP          string      `json:"client_ip"`
	ClaimedKey        string      `json:"claimed_key"`
	UserAgent         string      `json:"user_agent"`
	Payload           interface{} `json:"payload"`
	TranslatedPayload interface{} `json:"translated_payload,omitempty"`
	Response          interface{} `json:"response,omitempty"`
	RehydratedResp    interface{} `json:"rehydrated_resp,omitempty"`
}

func UploadAuditLogAsync(txID string, payload AuditLogPayload) {
	if GatewayConfig.ComplianceLoggingProvider == "none" {
		return
	}
	if GatewayConfig.ComplianceLoggingProvider == "local" {
		go uploadAuditLogLocal(txID, payload)
		return
	}

	if minioClient == nil || minioBucket == "" {
		return
	}

	select {
	case minioTaskQueue <- payload:
	default:
		// Queue full under peak traffic: log a warning
		log.Printf("[MinIO Error] Compliance logging queue is full. Dropping log: %s", txID)
	}
}

func uploadAuditLogLocal(txID string, payload AuditLogPayload) {
	dateStr := payload.Timestamp.Format("2006-01-02")
	dirPath := filepath.Join("/app/data/compliance_logs/audit", dateStr)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		log.Printf("[Local Log Error] Failed to create dir %s: %v", dirPath, err)
		return
	}

	prefix := ""
	if payload.IsBlocked {
		prefix = "blocked_"
	}
	filePath := filepath.Join(dirPath, fmt.Sprintf("%s%s.json", prefix, txID))

	fileData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Printf("[Local Log Error] Failed to marshal compliance audit log: %v", err)
		return
	}

	if err := os.WriteFile(filePath, fileData, 0644); err != nil {
		log.Printf("[Local Log Error] Failed to write file %s: %v", filePath, err)
	}
}

func uploadAuditLogSync(txID string, payload AuditLogPayload) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[MinIO Error] Failed to marshal compliance audit log: %v", err)
		return
	}

	prefix := ""
	if payload.IsBlocked {
		prefix = "blocked_"
	}
	objectName := fmt.Sprintf("audit/%s/%s%s.json", payload.Timestamp.Format("2006-01-02"), prefix, txID)
	reader := bytes.NewReader(data)

	_, err = minioClient.PutObject(ctx, minioBucket, objectName, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/json",
	})
	if err != nil {
		log.Printf("[MinIO Error] Failed to upload audit log %s: %v", txID, err)
	}
}

func LogComplianceAuditAsync(txID, sessionID string, observation int, vfeL1, vfeL2, vfeL3 float64, isBlocked bool, r *http.Request, body []byte, transReq []byte, rawResp []byte, transResp []byte) {
	if GatewayConfig.ComplianceLoggingProvider == "none" {
		return
	}
	if GatewayConfig.ComplianceLoggingProvider == "s3" && (minioClient == nil || minioBucket == "") {
		return
	}

	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}
	claimedKey := r.Header.Get("X-Agent-Key")
	if claimedKey == "" {
		claimedKey = r.Header.Get("Authorization")
	}
	userAgent := r.UserAgent()

	var parsedBody interface{}
	if len(body) > 0 {
		var temp map[string]interface{}
		if err := json.Unmarshal(body, &temp); err == nil {
			parsedBody = temp
		} else {
			parsedBody = string(body)
		}
	}

	var parsedTransReq interface{}
	if len(transReq) > 0 {
		var temp map[string]interface{}
		if err := json.Unmarshal(transReq, &temp); err == nil {
			parsedTransReq = temp
		} else {
			parsedTransReq = string(transReq)
		}
	}

	var parsedRawResp interface{}
	if len(rawResp) > 0 {
		var temp map[string]interface{}
		if err := json.Unmarshal(rawResp, &temp); err == nil {
			parsedRawResp = temp
		} else {
			parsedRawResp = string(rawResp)
		}
	}

	var parsedTransResp interface{}
	if len(transResp) > 0 {
		var temp map[string]interface{}
		if err := json.Unmarshal(transResp, &temp); err == nil {
			parsedTransResp = temp
		} else {
			parsedTransResp = string(transResp)
		}
	}

	UploadAuditLogAsync(txID, AuditLogPayload{
		TransactionID:     txID,
		SessionID:         sessionID,
		Observation:       observation,
		VFEScore:          vfeL2,
		VFEScoreL1:        vfeL1,
		VFEScoreL3:        vfeL3,
		IsBlocked:         isBlocked,
		Timestamp:         time.Now(),
		ClientIP:          clientIP,
		ClaimedKey:        claimedKey,
		UserAgent:         userAgent,
		Payload:           parsedBody,
		TranslatedPayload: parsedTransReq,
		Response:          parsedRawResp,
		RehydratedResp:    parsedTransResp,
	})
}

func clearMinIOBucket() {
	// Always clear local compliance logs directory on reset
	if err := os.RemoveAll("/app/data/compliance_logs"); err == nil {
		log.Println("[Local compliance] Local logs directory cleared successfully.")
	} else if !os.IsNotExist(err) {
		log.Printf("[Local Log Error] Failed to clear local logs directory: %v", err)
	}

	if minioClient == nil || minioBucket == "" {
		return
	}

	log.Println("[MinIO] System Reset: Clearing compliance bucket...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// List all versions to support force deletion on WORM object locking
	objectCh := minioClient.ListObjects(ctx, minioBucket, minio.ListObjectsOptions{
		Recursive:    true,
		WithVersions: GatewayConfig.MinioObjectLocking,
	})

	var wg sync.WaitGroup
	for obj := range objectCh {
		if obj.Err != nil {
			log.Printf("[MinIO Error] Failed to list version for deletion: %v", obj.Err)
			continue
		}
		wg.Add(1)
		go func(o minio.ObjectInfo) {
			defer wg.Done()
			_ = minioClient.RemoveObject(ctx, minioBucket, o.Key, minio.RemoveObjectOptions{
				VersionID:        o.VersionID,
				GovernanceBypass: true,
			})
		}(obj)
	}
	wg.Wait()

	// Try removing the bucket to completely recreate it
	err := minioClient.RemoveBucket(ctx, minioBucket)
	if err == nil {
		log.Printf("[MinIO] Successfully removed bucket '%s' for recreation", minioBucket)
		initMinIO()
	} else {
		log.Printf("[MinIO Warning] Failed to delete bucket '%s' for recreation (WORM lock may be active): %v", minioBucket, err)
		// Fallback clean delete of any non-locked objects
		objectChNonWorm := minioClient.ListObjects(ctx, minioBucket, minio.ListObjectsOptions{
			Recursive: true,
		})
		var wgFallback sync.WaitGroup
		for obj := range objectChNonWorm {
			if obj.Err == nil {
				wgFallback.Add(1)
				go func(o minio.ObjectInfo) {
					defer wgFallback.Done()
					_ = minioClient.RemoveObject(ctx, minioBucket, o.Key, minio.RemoveObjectOptions{})
				}(obj)
			}
		}
		wgFallback.Wait()
	}
}
