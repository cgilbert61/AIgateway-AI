package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// SecurityAuditEvent represents an audit trail log for active inference decisions
type SecurityAuditEvent struct {
	Timestamp     string  `json:"timestamp"`
	TxID          string  `json:"tx_id"`
	SessionID     string  `json:"session_id"`
	ClaimedKey    string  `json:"claimed_key"`
	BeliefState   string  `json:"belief_state"`
	Observation   string  `json:"observation"`
	VFE           float64 `json:"vfe"`
	Action        string  `json:"action"`
	Deduplicated  bool    `json:"deduplicated"`
}

// logSecurityAuditEvent serializes a security decision into structured JSON format
func logSecurityAuditEvent(txID string, sessionID string, claimedKey string, belief string, obs string, vfe float64, action string, deduplicated bool) {
	evt := SecurityAuditEvent{
		Timestamp:    time.Now().Format(time.RFC3339),
		TxID:         txID,
		SessionID:    sessionID,
		ClaimedKey:   claimedKey,
		BeliefState:  belief,
		Observation:  obs,
		VFE:          vfe,
		Action:       action,
		Deduplicated: deduplicated,
	}

	data, err := json.Marshal(evt)
	if err == nil {
		if !UnthrottledModeActive || action == "BLOCK" {
			fmt.Printf("[SECURITY_AUDIT_LOG] %s\n", string(data))
		}
	} else {
		log.Printf("[Error] Failed to marshal security audit event: %v", err)
	}
}
