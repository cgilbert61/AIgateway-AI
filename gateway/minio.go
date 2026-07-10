package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	minioClient *minio.Client
	minioBucket string
)

func initMinIO() {
	endpoint := os.Getenv("MINIO_ENDPOINT")
	accessKey := os.Getenv("MINIO_ACCESS_KEY")
	secretKey := os.Getenv("MINIO_SECRET_KEY")
	minioBucket = os.Getenv("MINIO_BUCKET_NAME")

	if endpoint == "" || accessKey == "" || secretKey == "" || minioBucket == "" {
		log.Println("[MinIO Warn] MinIO environmental variables not fully configured. Compliance archival is disabled.")
		return
	}

	var err error
	// Set up the client connection
	minioClient, err = minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
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
		log.Printf("[MinIO] Bucket '%s' does not exist. Creating with WORM Object Locking enabled...", minioBucket)
		createCtx, createCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = minioClient.MakeBucket(createCtx, minioBucket, minio.MakeBucketOptions{
			ObjectLocking: true,
		})
		createCancel()
		if err != nil {
			log.Printf("[MinIO Error] Failed to create bucket with object locking: %v", err)
			return
		}

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
		log.Printf("[MinIO] Bucket '%s' already exists and is active.", minioBucket)
	}
}

type AuditLogPayload struct {
	TransactionID string      `json:"transaction_id"`
	SessionID     string      `json:"session_id"`
	Observation   int         `json:"observation"`
	VFEScore      float64     `json:"vfe_score"`
	VFEScoreL1    float64     `json:"vfe_score_l1"`
	VFEScoreL3    float64     `json:"vfe_score_l3"`
	IsBlocked     bool        `json:"is_blocked"`
	Timestamp     time.Time   `json:"timestamp"`
	ClientIP      string      `json:"client_ip"`
	ClaimedKey    string      `json:"claimed_key"`
	UserAgent     string      `json:"user_agent"`
	Payload       interface{} `json:"payload"`
}

func UploadAuditLogAsync(txID string, payload AuditLogPayload) {
	if minioClient == nil || minioBucket == "" {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		data, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[MinIO Error] Failed to marshal compliance audit log: %v", err)
			return
		}

		objectName := fmt.Sprintf("audit/%s/%s.json", payload.Timestamp.Format("2006-01-02"), txID)
		reader := bytes.NewReader(data)

		_, err = minioClient.PutObject(ctx, minioBucket, objectName, reader, int64(len(data)), minio.PutObjectOptions{
			ContentType: "application/json",
		})
		if err != nil {
			log.Printf("[MinIO Error] Failed to upload audit log %s: %v", txID, err)
		} else {
			log.Printf("[MinIO] Successfully archived audit log %s to WORM storage.", txID)
		}
	}()
}

func LogComplianceAuditAsync(txID, sessionID string, observation int, vfeL1, vfeL2, vfeL3 float64, isBlocked bool, r *http.Request, body []byte) {
	if minioClient == nil || minioBucket == "" {
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

	UploadAuditLogAsync(txID, AuditLogPayload{
		TransactionID: txID,
		SessionID:     sessionID,
		Observation:   observation,
		VFEScore:      vfeL2,
		VFEScoreL1:    vfeL1,
		VFEScoreL3:    vfeL3,
		IsBlocked:     isBlocked,
		Timestamp:     time.Now(),
		ClientIP:      clientIP,
		ClaimedKey:    claimedKey,
		UserAgent:     userAgent,
		Payload:       parsedBody,
	})
}
