package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
	redisCtx    = context.Background()
)

// initRedis initializes the connection pool to the Redis instance
func initRedis() {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		log.Println("[Redis] REDIS_URL not set. Falling back to in-memory state management.")
		return
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:         redisURL,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		PoolSize:     150,
	})

	// Test connection
	_, err := redisClient.Ping(redisCtx).Result()
	if err != nil {
		log.Printf("[Redis Error] Failed to ping Redis at %s: %v. Falling back to in-memory state.", redisURL, err)
		redisClient = nil
	} else {
		log.Printf("[Redis] Successfully connected to Redis at %s.", redisURL)
		go subscribeSimulatorControl()
		go subscribeActiveInferenceReloads()
	}
}

// getRedisBeliefState retrieves the ActiveInfState for a session from Redis
func getRedisBeliefState(sessionID string) (*ActiveInfState, error) {
	if redisClient == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	key := fmt.Sprintf("beliefs:%s", sessionID)
	data, err := redisClient.Get(redisCtx, key).Bytes()
	if err != nil {
		return nil, err
	}

	var state ActiveInfState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	return &state, nil
}

// setRedisBeliefState stores the ActiveInfState for a session in Redis with 15 minutes TTL
func setRedisBeliefState(sessionID string, state *ActiveInfState) error {
	if redisClient == nil {
		return fmt.Errorf("redis client not initialized")
	}

	key := fmt.Sprintf("beliefs:%s", sessionID)
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// 15 minutes expiration for in-memory belief states
	return redisClient.Set(redisCtx, key, data, 15*time.Minute).Err()
}

// deleteRedisBeliefState deletes the belief state for a session
func deleteRedisBeliefState(sessionID string) error {
	if redisClient == nil {
		return fmt.Errorf("redis client not initialized")
	}

	key := fmt.Sprintf("beliefs:%s", sessionID)
	return redisClient.Del(redisCtx, key).Err()
}

// clearAllRedisBeliefStates deletes all cached belief states (used during reset)
func clearAllRedisBeliefStates() error {
	if redisClient == nil {
		return fmt.Errorf("redis client not initialized")
	}

	var cursor uint64
	for {
		keys, nextCursor, err := redisClient.Scan(redisCtx, cursor, "beliefs:*", 100).Result()
		if err != nil {
			return err
		}

		if len(keys) > 0 {
			if err := redisClient.Del(redisCtx, keys...).Err(); err != nil {
				return err
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

// GetSessionState attempts to fetch from local sessionCache first, falling back to Redis, and then PostgreSQL rehydration
func GetSessionState(sessionID string) (*ActiveInfState, bool) {
	// 1. Try Local Cache First (Ultra-fast, in-memory)
	val, ok := sessionCache.Load(sessionID)
	if ok {
		return val.(*ActiveInfState), true
	}

	// 2. Try Redis (Distributed fallback)
	if state, err := getRedisBeliefState(sessionID); err == nil && state != nil {
		// Cache locally to accelerate next lookups
		sessionCache.Store(sessionID, state)
		return state, true
	}

	// 3. Cache Miss: Rehydrate from PostgreSQL history (Write-Through/Cache-Aside)
	if DB != nil {
		a1, b1, theta, err := GetSessionMatrices(sessionID)
		if err == nil {
			state, err := RehydrateSessionState(sessionID, a1, b1, theta)
			if err == nil && state != nil {
				StoreSessionState(sessionID, state)
				return state, true
			}
		}
	}

	return nil, false
}

// StoreSessionState saves the state to both sessionCache and Redis
func StoreSessionState(sessionID string, state *ActiveInfState) {
	sessionCache.Store(sessionID, state)
	if redisClient != nil {
		data, err := json.Marshal(state)
		if err == nil {
			queueDBTask(func() {
				key := fmt.Sprintf("beliefs:%s", sessionID)
				_ = redisClient.Set(redisCtx, key, data, 15*time.Minute).Err()
			})
		}
	}
}

// DeleteSessionState removes the state from both sessionCache and Redis
func DeleteSessionState(sessionID string) {
	sessionCache.Delete(sessionID)
	_ = deleteRedisBeliefState(sessionID)
}

// ClearAllSessionStates clears all states from sessionCache and Redis
func ClearAllSessionStates() {
	sessionCache.Range(func(key, value interface{}) bool {
		sessionCache.Delete(key)
		return true
	})
	_ = clearAllRedisBeliefStates()
}

func subscribeSimulatorControl() {
	pubsub := redisClient.Subscribe(redisCtx, "simulator_control")
	defer pubsub.Close()

	ch := pubsub.Channel()
	for msg := range ch {
		switch msg.Payload {
		case "start":
			log.Println("[Redis PubSub] Received start command.")
			startSimulatorLocally()
		case "stop":
			log.Println("[Redis PubSub] Received stop command.")
			stopSimulatorLocally()
		}
	}
}

func subscribeActiveInferenceReloads() {
	if redisClient == nil {
		log.Println("[Redis PubSub] Skipping active_inference:reloads subscription: redisClient is nil")
		return
	}
	pubsub := redisClient.Subscribe(redisCtx, "active_inference:reloads")
	defer pubsub.Close()

	ch := pubsub.Channel()
	for msg := range ch {
		var req struct {
			SessionID     string        `json:"session_id"`
			L2Beliefs     []float64     `json:"l2_beliefs"`
			L2Action      int           `json:"l2_action"`
			L3VFE         float64       `json:"l3_vfe"`
			Layer1MatrixA [][]float64   `json:"layer1_matrix_a"`
			Layer1MatrixB [][][]float64 `json:"layer1_matrix_b"`
		}
		if err := json.Unmarshal([]byte(msg.Payload), &req); err != nil {
			log.Printf("[Redis PubSub Error] Failed to unmarshal reload message: %v", err)
			continue
		}

		sessUUID, err := resolveSessionUUID(req.SessionID)
		if err != nil {
			log.Printf("[Redis PubSub Error] Invalid session ID in reload message: %v", err)
			continue
		}
		uuidStr := sessUUID.String()

		state, ok := GetSessionState(uuidStr)
		if ok {
			state.Lock()
			if len(req.Layer1MatrixA) > 0 && len(req.Layer1MatrixB) > 0 {
				state.UpdateMatrices(req.Layer1MatrixA, req.Layer1MatrixB)
			}
			state.UpdateL2State(req.L2Beliefs, req.L2Action)
			state.HistoryL3VFE = append(state.HistoryL3VFE, req.L3VFE)
			StoreSessionState(uuidStr, state)
			state.Unlock()
		}
	}
}
