package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	DB                  *sql.DB
	DefaultMatrixA1     [][]float64
	DefaultMatrixB1     [][][]float64
	DefaultMatrixA2     [][]float64
	DefaultMatrixB2     [][][]float64
	DefaultMatrixC2     []float64
	DefaultTheta        float64
	matricesLoaded      bool

	localDeltaRequests  uint64
	localDeltaBlocks    uint64
	localTotalLatencyUs uint64
	localLatencyCount   uint64

	sessionNameCache    sync.Map // uuid_string -> original_session_id
)

type dbTask func()
var dbTaskQueue = make(chan dbTask, 100000)

func queueDBTask(task dbTask) {
	select {
	case dbTaskQueue <- task:
	default:
		// Queue full under peak traffic: drop telemetry log to protect system health
	}
}

func ClearDBTaskQueue() {
	for {
		select {
		case <-dbTaskQueue:
		default:
			return
		}
	}
}

// SeedingConfig matches the JSON structure in default_matrices.json
type SeedingConfig struct {
	Layer1A [][]float64   `json:"layer1_matrix_a"`
	Layer1B [][][]float64 `json:"layer1_matrix_b"`
	Layer2A [][]float64   `json:"layer2_matrix_a"`
	Layer2B [][][]float64 `json:"layer2_matrix_b"`
	Layer2C []float64     `json:"layer2_matrix_c"`
	Theta   float64       `json:"threshold_theta"`
}

// InitDB initializes PostgreSQL connection pool and seeds default matrices if empty
func InitDB() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgresql://user:password@postgres_db:5432/postgres?sslmode=disable"
	}

	var err error
	for i := 0; i < 15; i++ {
		DB, err = sql.Open("postgres", dbURL)
		if err == nil {
			err = DB.Ping()
			if err == nil {
				log.Println("Successfully connected to PostgreSQL database.")
				DB.SetMaxOpenConns(25)
				DB.SetMaxIdleConns(15)
				DB.SetConnMaxLifetime(10 * time.Minute)
				_, _ = DB.Exec("ALTER TABLE runtime_inference_state ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT FALSE")
				_, _ = DB.Exec(`
					CREATE TABLE IF NOT EXISTS entity_historical_surprise (
						entity_key VARCHAR(255) PRIMARY KEY,
						accumulated_surprise DOUBLE PRECISION DEFAULT 0.0,
						total_requests BIGINT DEFAULT 0,
						total_blocks BIGINT DEFAULT 0,
						total_pii BIGINT DEFAULT 0,
						total_injections BIGINT DEFAULT 0,
						last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
					)
				`)
				_, _ = DB.Exec(`
					CREATE TABLE IF NOT EXISTS system_metrics (
						metric_key VARCHAR(50) PRIMARY KEY,
						metric_value BIGINT DEFAULT 0
					)
				`)
				_, _ = DB.Exec("INSERT INTO system_metrics (metric_key, metric_value) VALUES ('total_requests', 0), ('total_blocks', 0) ON CONFLICT DO NOTHING")

				// Create agent monitoring tables
				_, _ = DB.Exec(`
					CREATE TABLE IF NOT EXISTS authorized_agent_keys (
						key_id VARCHAR(255) PRIMARY KEY,
						agent_name VARCHAR(255) NOT NULL,
						is_active BOOLEAN DEFAULT TRUE,
						registered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
					)
				`)

				// Seed the 15 rogue agents
				_, _ = DB.Exec(`
					INSERT INTO authorized_agent_keys (key_id, agent_name, is_active) VALUES
					('agent-retro-sysop', 'Retro Sysop Agent', true),
					('agent-chaos-monkey', 'Chaos Monkey Agent', true),
					('agent-ghost-coder', 'Ghost Coder Agent', true),
					('agent-network-sentinel', 'Network Sentinel Agent', true),
					('agent-disk-sanitizer', 'Disk Sanitizer Agent', true),
					('agent-memory-checker', 'Memory Checker Agent', true),
					('agent-dependency-auditor', 'Dependency Auditor Agent', true),
					('agent-log-rotator', 'Log Rotator Agent', true),
					('agent-telemetry-mesh', 'Telemetry Mesh Agent', true),
					('agent-labs-dj', 'Labs DJ Agent', true),
					('agent-truth-engine', 'Truth Engine Agent', true),
					('agent-doc-summarizer', 'Doc Summarizer Agent', true),
					('agent-exfil-crawler', 'Exfil Crawler Agent', true),
					('agent-credential-harvester', 'Credential Harvester Agent', true),
					('agent-fuzz-tester', 'Fuzz Tester Agent', true),
					('agent-system-tester', 'System Test Agent', true)
					ON CONFLICT (key_id) DO NOTHING
				`)

				_, _ = DB.Exec(`
					CREATE TABLE IF NOT EXISTS agent_forensic_log (
						id VARCHAR(36) PRIMARY KEY,
						timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
						client_ip VARCHAR(255) NOT NULL,
						claimed_key VARCHAR(255) NOT NULL,
						user_agent VARCHAR(255) NOT NULL,
						attempted_payload TEXT NOT NULL,
						reason VARCHAR(255) NOT NULL
					)
				`)
				_, _ = DB.Exec(`
					CREATE TABLE IF NOT EXISTS session_quarantine (
						session_id VARCHAR(255) PRIMARY KEY,
						status VARCHAR(30) DEFAULT 'QUARANTINED',
						reason VARCHAR(255) DEFAULT '',
						quarantined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
						decided_at TIMESTAMP WITH TIME ZONE
					)
				`)
				_, _ = DB.Exec(`
					CREATE TABLE IF NOT EXISTS siem_config (
						provider VARCHAR(50) PRIMARY KEY,
						endpoint_url VARCHAR(255) NOT NULL,
						auth_token VARCHAR(255) NOT NULL,
						is_active BOOLEAN DEFAULT FALSE
					)
				`)
				break
			}
		}
		log.Printf("Waiting for database connection (retry %d/15): %v", i+1, err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Fatalf("Fatal: could not connect to PostgreSQL database: %v", err)
	}

	// Spawn the DB background worker pool (80 concurrent workers draining the task queue)
	for i := 0; i < 80; i++ {
		go func() {
			for task := range dbTaskQueue {
				task()
			}
		}()
	}

	loadDefaultMatrices()

	// Start database pruner background routine to retain only the latest 1000 transactions
	StartDBPruner(30*time.Second, 1000)

	// Start batch metrics syncer background routine to push metrics every 1 second
	StartMetricsSyncer(1 * time.Second)
}

// loadDefaultMatrices reads the default json files and caches them
func loadDefaultMatrices() {
	configPath := os.Getenv("DEFAULT_MATRICES_PATH")
	if configPath == "" {
		configPath = "/app/config/default_matrices.json"
	}

	file, err := os.Open(configPath)
	if err != nil {
		log.Printf("Warning: default_matrices.json not found at %s, attempting fallback: %v", configPath, err)
		// Fallback for local testing
		file, err = os.Open("../config/default_matrices.json")
		if err != nil {
			log.Fatalf("Fatal: could not load default matrices config: %v", err)
		}
	}
	defer file.Close()

	var cfg SeedingConfig
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		log.Fatalf("Fatal: failed to decode default matrices JSON: %v", err)
	}

	DefaultMatrixA1 = cfg.Layer1A
	DefaultMatrixB1 = cfg.Layer1B
	DefaultMatrixA2 = cfg.Layer2A
	DefaultMatrixB2 = cfg.Layer2B
	DefaultMatrixC2 = cfg.Layer2C
	DefaultTheta = cfg.Theta
	matricesLoaded = true
	log.Println("Loaded default active inference matrices from configuration file.")
}

func resolveSessionUUID(sessionID string) (uuid.UUID, error) {
	u, err := uuid.Parse(sessionID)
	if err == nil {
		return u, nil
	}
	res := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(sessionID))
	sessionNameCache.Store(res.String(), sessionID)
	return res, nil
}

func initSessionNameCache() {
	agentKeys := []string{
		"agent-retro-sysop",
		"agent-chaos-monkey",
		"agent-ghost-coder",
		"agent-network-sentinel",
		"agent-disk-sanitizer",
		"agent-memory-checker",
		"agent-dependency-auditor",
		"agent-log-rotator",
		"agent-telemetry-mesh",
		"agent-labs-dj",
		"agent-truth-engine",
		"agent-doc-summarizer",
		"agent-exfil-crawler",
		"agent-credential-harvester",
		"agent-fuzz-tester",
		"agent-system-tester",
	}
	for _, key := range agentKeys {
		fleetSessID := fmt.Sprintf("fleet-loop-%s", key)
		u := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(fleetSessID))
		sessionNameCache.Store(u.String(), fleetSessID)

		uKey := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(key))
		sessionNameCache.Store(uKey.String(), key)
	}

	for i := 1; i <= 1000; i++ {
		sessID := fmt.Sprintf("sim-worker-%d", i)
		u := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(sessID))
		sessionNameCache.Store(u.String(), sessID)
	}
}

// GetSessionMatrices loads active profile matrices from database, or seeds and returns defaults if missing
func GetSessionMatrices(sessionID string) ([][]float64, [][][]float64, float64, error) {
	if !matricesLoaded {
		return nil, nil, 0, fmt.Errorf("default matrices not loaded")
	}

	sessUUID, err := resolveSessionUUID(sessionID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("invalid session uuid: %v", err)
	}

	var rawA1, rawB1 []byte
	var theta float64

	err = DB.QueryRow(
		`SELECT layer1_matrix_a, layer1_matrix_b, threshold_theta 
		 FROM agent_profile_matrices WHERE session_id = $1`,
		sessUUID,
	).Scan(&rawA1, &rawB1, &theta)

	if err == sql.ErrNoRows {
		// Session does not exist yet. Seed defaults into DB.
		log.Printf("Session ID %s not found in DB. Seeding defaults...", sessionID)
		
		a1JSON, _ := json.Marshal(DefaultMatrixA1)
		b1JSON, _ := json.Marshal(DefaultMatrixB1)
		a2JSON, _ := json.Marshal(DefaultMatrixA2)
		b2JSON, _ := json.Marshal(DefaultMatrixB2)
		c2JSON, _ := json.Marshal(DefaultMatrixC2)

		_, err = DB.Exec(
			`INSERT INTO agent_profile_matrices (
				session_id, layer1_matrix_a, layer1_matrix_b, 
				layer2_matrix_a, layer2_matrix_b, layer2_matrix_c, threshold_theta
			 ) VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (session_id) DO NOTHING`,
			sessUUID, a1JSON, b1JSON, a2JSON, b2JSON, c2JSON, DefaultTheta,
		)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to auto-seed session matrices in DB: %v", err)
		}

		return DefaultMatrixA1, DefaultMatrixB1, DefaultTheta, nil
	} else if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to query session matrices: %v", err)
	}

	var a1 [][]float64
	var b1 [][][]float64
	if err := json.Unmarshal(rawA1, &a1); err != nil {
		return nil, nil, 0, err
	}
	if err := json.Unmarshal(rawB1, &b1); err != nil {
		return nil, nil, 0, err
	}
	return a1, b1, theta, nil
}

type RedisLogEntry struct {
	TransactionID     string    `json:"transaction_id"`
	SessionID         string    `json:"session_id"`
	ObservationVector []int64   `json:"observation_vector"`
	VFEScore          float64   `json:"vfe_score"`
	VFEScoreL1        float64   `json:"vfe_score_l1"`
	VFEScoreL3        float64   `json:"vfe_score_l3"`
	IsBlocked         bool      `json:"is_blocked"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// LogTransactionState logs observations and VFE scores. If Redis is connected, writes to Redis list; else falls back to PostgreSQL.
func LogTransactionState(txID, sessionID string, observation int, vfeL1, vfeL2, vfeL3 float64, isBlocked bool) error {
	sessUUID, err := resolveSessionUUID(sessionID)
	if err != nil {
		return err
	}
	uuidStr := sessUUID.String()

	if redisClient != nil {
		entry := RedisLogEntry{
			TransactionID:     txID,
			SessionID:         uuidStr,
			ObservationVector: []int64{int64(observation)},
			VFEScore:          vfeL2,
			VFEScoreL1:        vfeL1,
			VFEScoreL3:        vfeL3,
			IsBlocked:         isBlocked,
			UpdatedAt:         time.Now(),
		}
		data, err := json.Marshal(entry)
		if err == nil {
			err = redisClient.LPush(redisCtx, "active_inference:logs", data).Err()
			if err == nil {
				redisClient.LTrim(redisCtx, "active_inference:logs", 0, 999)
				// Publish asynchronously/directly to Redis Pub/Sub channel
				_ = redisClient.Publish(redisCtx, "active_inference:transactions", data).Err()

				atomic.AddUint64(&localDeltaRequests, 1)
				if isBlocked {
					atomic.AddUint64(&localDeltaBlocks, 1)
				}
				return nil
			}
		}
	}

	txUUID, err := uuid.Parse(txID)
	if err != nil {
		return err
	}

	obsVector := []int64{int64(observation)}

	_, err = DB.Exec(
		`INSERT INTO runtime_inference_state (
			transaction_id, session_id, observation_vector, vfe_score, vfe_score_l1, vfe_score_l3, is_blocked, updated_at
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		txUUID, sessUUID, pq.Array(obsVector), vfeL2, vfeL1, vfeL3, isBlocked,
	)
	if err != nil {
		return err
	}

	atomic.AddUint64(&localDeltaRequests, 1)
	if isBlocked {
		atomic.AddUint64(&localDeltaBlocks, 1)
	}
	return nil
}

// StartDBPruner spawns a background goroutine that periodically prunes the database
// to keep only the latest maxRows records in the runtime_inference_state table.
func StartDBPruner(interval time.Duration, maxRows int) {
	go func() {
		ticker := time.NewTicker(interval)
		log.Printf("[DB_PRUNER] Started database history pruner background worker (interval: %v, maxRows: %d).", interval, maxRows)
		for range ticker.C {
			var count int
			err := DB.QueryRow("SELECT COUNT(*) FROM runtime_inference_state").Scan(&count)
			if err != nil {
				log.Printf("[DB_PRUNER] Error counting rows: %v", err)
				continue
			}

			if count <= maxRows {
				continue
			}

			res, err := DB.Exec(`
				DELETE FROM runtime_inference_state 
				WHERE updated_at < COALESCE((
					SELECT updated_at 
					FROM runtime_inference_state 
					ORDER BY updated_at DESC 
					OFFSET $1 LIMIT 1
				), '1970-01-01 00:00:00+00'::timestamptz)
			`, maxRows)
			if err != nil {
				log.Printf("[DB_PRUNER] Error pruning old transactions: %v", err)
			} else {
				rowsDeleted, _ := res.RowsAffected()
				if rowsDeleted > 0 {
					log.Printf("[DB_PRUNER] Successfully pruned %d old transaction logs (Current total: %d, Target: %d).", rowsDeleted, count, maxRows)
				}
			}
		}
	}()
}

// LogEntityHistoricalState records cross-session entity behaviors for Layer 4 reports
func LogEntityHistoricalState(entityKey string, isBlocked bool, observation int, vfe float64) {
	if entityKey == "" {
		return
	}

	piiInc := 0
	if observation == 2 { // OBS_INPUT_ERROR
		piiInc = 1
	}

	blockInc := 0
	if isBlocked {
		blockInc = 1
	}

	_, err := DB.Exec(`
		INSERT INTO entity_historical_surprise (
			entity_key, accumulated_surprise, total_requests, total_blocks, total_pii, total_injections, last_active_at
		) VALUES ($1, $4, 1, $2, $3, 0, NOW())
		ON CONFLICT (entity_key) DO UPDATE SET
			accumulated_surprise = entity_historical_surprise.accumulated_surprise * EXP(-EXTRACT(EPOCH FROM (NOW() - entity_historical_surprise.last_active_at)) * 0.00001) + $4,
			total_requests = entity_historical_surprise.total_requests + 1,
			total_blocks = entity_historical_surprise.total_blocks + $2,
			total_pii = entity_historical_surprise.total_pii + $3,
			last_active_at = NOW()
	`, entityKey, blockInc, piiInc, vfe)
	
	if err != nil {
		log.Printf("[L4 Elephant] Error updating entity historical surprise: %v", err)
	}
}

// RehydrateSessionState queries PostgreSQL for transaction history and reconstructs the active inference belief state
func RehydrateSessionState(sessionID string, a1 [][]float64, b1 [][][]float64, theta float64) (*ActiveInfState, error) {
	sessUUID, err := resolveSessionUUID(sessionID)
	if err != nil {
		return nil, err
	}

	state := NewActiveInfState(a1, b1)
	state.Theta = theta
	state.SessionUUID = sessUUID.String()

	rows, err := DB.Query(`
		SELECT observation_vector, is_blocked
		FROM runtime_inference_state 
		WHERE session_id = $1 
		ORDER BY updated_at ASC`, sessUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to query transaction history: %w", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var obsArr []int64
		var isBlocked bool
		if err := rows.Scan(pq.Array(&obsArr), &isBlocked); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if len(obsArr) == 0 {
			continue
		}
		obs := int(obsArr[0])

		var prevAction *int
		if len(state.HistoryAction) > 0 {
			act := state.HistoryAction[len(state.HistoryAction)-1]
			prevAction = &act
		}

		// Replay perception updates
		state.UpdateL1Perception(prevAction, obs)
		state.UpdatePerception(prevAction, obs)

		// Determine action
		qPi, _ := state.SelectActionEFE(state.PriorBeliefs, GatewayConfig.L2PrecisionGamma)
		decidedAction := ACTION_ALLOW
		maxProb := -1.0
		for a, prob := range qPi {
			if prob > maxProb {
				maxProb = prob
				decidedAction = a
			}
		}

		// Apply threshold
		if state.Theta < 4.95 && state.LeakyVFE > state.Theta {
			decidedAction = ACTION_BLOCK
		} else if decidedAction == ACTION_BLOCK {
			decidedAction = ACTION_MONITOR
		}

		state.CurrentAction = decidedAction
		state.CurrentObs = obs
		state.HistoryAction = append(state.HistoryAction, decidedAction)
		count++
	}

	if count > 0 {
		log.Printf("[Write-Through Cache] Successfully rehydrated session state for %s from %d historical DB transactions.", sessionID, count)
	}

	return state, nil
}

// StartMetricsSyncer runs a background worker that regularly pushes accumulated metrics to DB
func StartMetricsSyncer(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		for range ticker.C {
			reqs := atomic.SwapUint64(&localDeltaRequests, 0)
			blks := atomic.SwapUint64(&localDeltaBlocks, 0)
			if DB == nil {
				continue
			}
			if reqs > 0 {
				_, _ = DB.Exec("UPDATE system_metrics SET metric_value = metric_value + $1 WHERE metric_key = 'total_requests'", reqs)
			}
			if blks > 0 {
				_, _ = DB.Exec("UPDATE system_metrics SET metric_value = metric_value + $1 WHERE metric_key = 'total_blocks'", blks)
			}
		}
	}()
}

// ResetLocalMetrics clears the in-memory metric buffers
func ResetLocalMetrics() {
	atomic.StoreUint64(&localDeltaRequests, 0)
	atomic.StoreUint64(&localDeltaBlocks, 0)
	atomic.StoreUint64(&localTotalLatencyUs, 0)
	atomic.StoreUint64(&localLatencyCount, 0)
}

func RecordRequestLatency(start time.Time) {
	durationUs := uint64(time.Since(start).Microseconds())
	atomic.AddUint64(&localTotalLatencyUs, durationUs)
	atomic.AddUint64(&localLatencyCount, 1)
}

func GetAverageLatencyMs() float64 {
	count := atomic.LoadUint64(&localLatencyCount)
	if count == 0 {
		return 0.0
	}
	totalUs := atomic.LoadUint64(&localTotalLatencyUs)
	return float64(totalUs) / float64(count) / 1000.0
}

func LogTransactionStateAsync(txID, sessionID string, observation int, vfeL1, vfeL2, vfeL3 float64, isBlocked bool) {
	queueDBTask(func() {
		err := LogTransactionState(txID, sessionID, observation, vfeL1, vfeL2, vfeL3, isBlocked)
		if err != nil {
			log.Printf("[Error] Failed to log transaction state: %v", err)
		}
	})
}

func LogEntityHistoricalStateAsync(entityKey string, isBlocked bool, observation int, vfe float64) {
	queueDBTask(func() {
		LogEntityHistoricalState(entityKey, isBlocked, observation, vfe)
	})
}

func LogForensicEventAsync(fId, ip, key, ua, payload, rsn string) {
	queueDBTask(func() {
		if DB == nil {
			return
		}
		_, dbErr := DB.Exec(`
			INSERT INTO agent_forensic_log (id, timestamp, client_ip, claimed_key, user_agent, attempted_payload, reason)
			VALUES ($1, NOW(), $2, $3, $4, $5, $6)
		`, fId, ip, key, ua, payload, rsn)
		if dbErr != nil {
			log.Printf("[Error] Failed to insert agent forensic log: %v", dbErr)
		}
	})
}

func IsSessionQuarantined(sessionID string) (bool, error) {
	if DB == nil {
		return false, nil
	}
	sessUUID, err := resolveSessionUUID(sessionID)
	if err != nil {
		return false, err
	}
	uuidStr := sessUUID.String()

	var status string
	err = DB.QueryRow("SELECT status FROM session_quarantine WHERE session_id = $1", uuidStr).Scan(&status)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return status == "QUARANTINED", nil
}

func QuarantineSession(sessionID string, reason string) error {
	if DB == nil {
		return nil
	}
	sessUUID, err := resolveSessionUUID(sessionID)
	if err != nil {
		return err
	}
	uuidStr := sessUUID.String()

	_, err = DB.Exec(`
		INSERT INTO session_quarantine (session_id, status, reason, quarantined_at, decided_at)
		VALUES ($1, 'QUARANTINED', $2, NOW(), NULL)
		ON CONFLICT (session_id) DO UPDATE SET status = 'QUARANTINED', reason = $2, quarantined_at = NOW(), decided_at = NULL
	`, uuidStr, reason)
	return err
}

func ResolveQuarantine(sessionID string, approved bool) error {
	if DB == nil {
		return nil
	}
	sessUUID, err := resolveSessionUUID(sessionID)
	if err != nil {
		return err
	}
	uuidStr := sessUUID.String()

	status := "REJECTED"
	if approved {
		status = "APPROVED"
	}
	_, err = DB.Exec(`
		UPDATE session_quarantine SET status = $1, decided_at = NOW() WHERE session_id = $2
	`, status, uuidStr)
	return err
}

type SIEMConfig struct {
	Provider    string `json:"provider"`
	EndpointURL string `json:"endpoint_url"`
	AuthToken   string `json:"auth_token"`
	IsActive    bool   `json:"is_active"`
}

func GetSIEMConfig(provider string) (*SIEMConfig, error) {
	if DB == nil {
		return nil, nil
	}
	var cfg SIEMConfig
	err := DB.QueryRow("SELECT provider, endpoint_url, auth_token, is_active FROM siem_config WHERE provider = $1", provider).Scan(&cfg.Provider, &cfg.EndpointURL, &cfg.AuthToken, &cfg.IsActive)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &cfg, nil
}

func SaveSIEMConfig(cfg *SIEMConfig) error {
	if DB == nil {
		return nil
	}
	_, err := DB.Exec(`
		INSERT INTO siem_config (provider, endpoint_url, auth_token, is_active)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (provider) DO UPDATE SET endpoint_url = $2, auth_token = $3, is_active = $4
	`, cfg.Provider, cfg.EndpointURL, cfg.AuthToken, cfg.IsActive)
	return err
}


