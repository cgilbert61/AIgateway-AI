package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
)

var (
	rateMutex  sync.Mutex
	rateStore  = make(map[string][]time.Time)
	ssnRegex   = regexp.MustCompile(`\b\d{3}[- ]?\d{2}[- ]?\d{4}\b`)
	ccRegex    = regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b|\b\d{16}\b`)
	phoneRegex = regexp.MustCompile(`\b(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b`)
	emailRegex = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	addrRegex  = regexp.MustCompile(`\b\d{1,5}\s+[A-Za-z0-9#.\s]{3,40}\s+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Boulevard|Blvd)\b`)
	preparedRegoQuery *rego.PreparedEvalQuery
	regoCompileMutex  sync.RWMutex
)

// AgentPayload captures standard and JSON-RPC tool parameters
type AgentPayload struct {
	Method string `json:"method"`
	Tool   string `json:"tool"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
	Args json.RawMessage `json:"args"`
}

// ClassifyRequest runs Layer 1 Active Inference over request tokens to produce Layer 2 observations
func ClassifyRequest(sessionID string, body []byte, isAgentRoute bool, state *ActiveInfState) int {
	// 1. Ingress Flood checks: Max request size (50KB)
	if len(body) > 50000 {
		state.HistoryL1VFE = append(state.HistoryL1VFE, 8.0) // high VFE for sizing anomaly
		return OBS_INGRESS_FLOOD
	}

	// 2. Ingress Flood checks: High frequency requests (Rate limit: 5 req per 2 seconds)
	if sessionID != "" && !checkRateLimit(sessionID) {
		state.HistoryL1VFE = append(state.HistoryL1VFE, 8.0) // high VFE for rate anomaly
		return OBS_INGRESS_FLOOD
	}

	// 3. Syntax checks: Valid JSON parsing
	var parseError bool
	if len(body) > 0 {
		var js map[string]interface{}
		if err := json.Unmarshal(body, &js); err != nil {
			parseError = true
		}
	} else if isAgentRoute {
		parseError = true
	}

	if parseError {
		state.HistoryL1VFE = append(state.HistoryL1VFE, 6.0) // medium-high VFE for parsing error
		return OBS_INPUT_ERROR
	}

	// 4. Layer 1 Active Inference: Parse tokens and evaluate syntactic surprise
	tokens := ScanRequestTokens(body)
	var totalL1VFE float64

	// Use default ACTION_ALLOW (0) for Layer 1 token transitions to ensure request-level statelessness.
	// This prevents the previous request's decided action (e.g. BLOCK) from leaking into the token transitions.
	l1Action := ACTION_ALLOW

	// Reset Layer 1 beliefs to baseline at the start of every request to make it stateless
	state.L1Beliefs = []float64{GatewayConfig.L1BaselineSafe, GatewayConfig.L1BaselineSusp, GatewayConfig.L1BaselineMal}

	for _, tok := range tokens {
		_, vfe := state.UpdateL1Perception(&l1Action, tok)
		totalL1VFE += vfe
	}

	avgL1VFE := 0.0
	if len(tokens) > 0 {
		avgL1VFE = totalL1VFE / float64(len(tokens))
	}

	textToScan := string(body)
	if !isAgentRoute {
		var chatReq struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(body, &chatReq); err == nil && len(chatReq.Messages) > 0 {
			textToScan = chatReq.Messages[len(chatReq.Messages)-1].Content
		}
	}

	hasPII := ssnRegex.MatchString(textToScan) || ccRegex.MatchString(textToScan) || emailRegex.MatchString(textToScan) || phoneRegex.MatchString(textToScan) || addrRegex.MatchString(textToScan)

	textBody := strings.ToLower(textToScan)
	injectionKeywords := []string{
		"ignore previous rules", "ignore instructions", "system prompt override", "ignore the instructions",
		"bypass safety", "jailbreak", "select * from", "union select", "' or 1=1",
	}
	hasInjection := false
	for _, kw := range injectionKeywords {
		if strings.Contains(textBody, kw) {
			hasInjection = true
			break
		}
	}

	if hasPII || hasInjection {
		avgL1VFE = 4.2
	}

	state.HistoryL1VFE = append(state.HistoryL1VFE, avgL1VFE)

	// Bottom-up Surprise Mapping:
	// If syntactic surprise (VFE) is high, map to appropriate L2 observation
	if avgL1VFE > 2.0 {
		if hasPII || hasInjection {
			return OBS_INPUT_ERROR
		}
		return OBS_STRUCTURE_SHIFT
	}

	// Heuristics fallback for agent actions (e.g. dangerous command keywords)
	if isAgentRoute {
		var payload AgentPayload
		_ = json.Unmarshal(body, &payload)
		toolName := ""
		if payload.Tool != "" {
			toolName = payload.Tool
		} else if payload.Params.Name != "" {
			toolName = payload.Params.Name
		}
		toolName = strings.ToLower(toolName)
		if toolName != "" {
			dangerousKeywords := []string{
				"write", "delete", "rm", "sh", "bash", "cmd", "execute", 
				"kill", "destroy", "system", "run", "inject",
			}
			for _, key := range dangerousKeywords {
				if strings.Contains(toolName, key) {
					return OBS_STRUCTURE_SHIFT
				}
			}
		}
	}

	return OBS_READ
}

// checkRateLimit implements sliding window rate limiting per session
func checkRateLimit(sessionID string) bool {
	rateMutex.Lock()
	defer rateMutex.Unlock()

	now := time.Now()
	window := 2 * time.Second
	limit := 15

	times, exists := rateStore[sessionID]
	if !exists {
		rateStore[sessionID] = []time.Time{now}
		return true
	}

	// Keep times within the window
	var validTimes []time.Time
	for _, t := range times {
		if now.Sub(t) <= window {
			validTimes = append(validTimes, t)
		}
	}

	validTimes = append(validTimes, now)
	rateStore[sessionID] = validTimes

	return len(validTimes) <= limit
}

// RedactPII replaces PII patterns in the request body with unique placeholder tokens
func RedactPII(body []byte) ([]byte, map[string]string) {
	if len(body) == 0 {
		return body, nil
	}
	text := string(body)
	rehydrateMap := make(map[string]string)
	counter := 1

	replaceFunc := func(re *regexp.Regexp, placeholderPrefix string) {
		text = re.ReplaceAllStringFunc(text, func(match string) string {
			placeholder := fmt.Sprintf("[%s_%d]", placeholderPrefix, counter)
			rehydrateMap[placeholder] = match
			counter++
			return placeholder
		})
	}

	replaceFunc(ssnRegex, "REDACTED_SSN")
	replaceFunc(ccRegex, "REDACTED_CC")
	replaceFunc(emailRegex, "REDACTED_EMAIL")
	replaceFunc(phoneRegex, "REDACTED_PHONE")
	replaceFunc(addrRegex, "REDACTED_ADDRESS")

	return []byte(text), rehydrateMap
}

// RehydrateResponse replaces PII placeholder tokens in the response body with original values
func RehydrateResponse(body []byte, rehydrateMap map[string]string) []byte {
	if len(body) == 0 || len(rehydrateMap) == 0 {
		return body
	}
	text := string(body)
	for placeholder, original := range rehydrateMap {
		text = strings.ReplaceAll(text, placeholder, original)
	}
	return []byte(text)
}

// Layer 1 Syntactic Observations
const (
	OBS_L1_ALPHANUMERIC = 0 // standard letters and numbers
	OBS_L1_SYNTAX_CHAR   = 1 // JSON syntax/braces
	OBS_L1_SPECIAL_CHAR  = 2 // SQL quotes, semi-colons
	OBS_L1_CONTROL_CHAR  = 3 // whitespace, control, binary
)

// ScanRequestTokens parses the raw request payload into categorical Layer 1 observations
func ScanRequestTokens(body []byte) []int {
	if len(body) == 0 {
		return []int{}
	}

	var tokens []int
	runes := []rune(string(body))

	// Limit to first 100 character/token observations to maintain 60FPS dashboard updates
	limit := 100
	if len(runes) < limit {
		limit = len(runes)
	}

	for i := 0; i < limit; i++ {
		r := runes[i]
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			tokens = append(tokens, OBS_L1_ALPHANUMERIC)
		} else if r == '{' || r == '}' || r == '[' || r == ']' || r == ':' || r == ',' {
			tokens = append(tokens, OBS_L1_SYNTAX_CHAR)
		} else if r == ';' || r == '\'' || r == '"' || r == '-' || r == '/' || r == '\\' || r == '<' || r == '>' || r == '=' {
			tokens = append(tokens, OBS_L1_SPECIAL_CHAR)
		} else {
			tokens = append(tokens, OBS_L1_CONTROL_CHAR)
		}
	}
	return tokens
}

// CompileRegoPolicy reads the tool policy from disk and prepares the OPA query for ultra-fast, concurrent evaluations
func CompileRegoPolicy() error {
	ctx := context.Background()
	policyPath := os.Getenv("REGO_POLICY_PATH")
	if policyPath == "" {
		policyPath = "/app/policies/tool_policy.rego"
	}
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		policyPath = "./policies/tool_policy.rego"
		if _, err := os.Stat(policyPath); os.IsNotExist(err) {
			policyPath = "../gateway/policies/tool_policy.rego"
		}
	}

	r := rego.New(
		rego.Query("data.gateway.authz.decision"),
		rego.Load([]string{policyPath}, nil),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return err
	}

	regoCompileMutex.Lock()
	preparedRegoQuery = &pq
	regoCompileMutex.Unlock()
	return nil
}

// EvaluatePolicy runs the pre-compiled OPA/Rego engine to check if a request complies with security rules
func EvaluatePolicy(role string, body []byte, isAgentRoute bool) (bool, string, error) {
	ctx := context.Background()

	// Parse payload body as arbitrary JSON structure to pass to input context
	var payload interface{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &payload)
	}

	// Construct input context
	input := map[string]interface{}{
		"role":           role,
		"is_agent_route": isAgentRoute,
		"payload":        payload,
	}

	regoCompileMutex.RLock()
	pq := preparedRegoQuery
	regoCompileMutex.RUnlock()

	if pq == nil {
		// Lazy-compile fallback if not pre-compiled at startup
		if err := CompileRegoPolicy(); err == nil {
			regoCompileMutex.RLock()
			pq = preparedRegoQuery
			regoCompileMutex.RUnlock()
		} else {
			return false, "", fmt.Errorf("failed to compile Rego policy: %v", err)
		}
	}

	// Evaluate the query with input
	results, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, "", fmt.Errorf("failed to evaluate Rego policy: %v", err)
	}

	if len(results) == 0 {
		return false, "Policy evaluation returned no decision results.", nil
	}

	// Extract the decision object output
	decisionMap, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return false, "Policy decision output has invalid structure.", nil
	}

	allowVal, ok1 := decisionMap["allow"].(bool)
	reasonVal, ok2 := decisionMap["reason"].(string)

	if !ok1 || !ok2 {
		return false, "Policy decision is missing 'allow' or 'reason' fields.", nil
	}

	return allowVal, reasonVal, nil
}
