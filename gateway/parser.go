package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
	redis "github.com/redis/go-redis/v9"
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

func isEntityEnabled(entityName string) bool {
	entitiesStr := GatewayConfig.DLPPresidioEntities
	if entitiesStr == "none" {
		return false
	}
	if entitiesStr == "" {
		// Default enabled entities if none configured
		defaultEntities := map[string]bool{
			"PERSON": true, "LOCATION": true, "ORGANIZATION": true, "DATE_TIME": true,
			"EMAIL_ADDRESS": true, "PHONE_NUMBER": true, "CREDIT_CARD": true, "US_SSN": true,
		}
		return defaultEntities[entityName]
	}
	parts := strings.Split(entitiesStr, ",")
	for _, p := range parts {
		if strings.TrimSpace(p) == entityName {
			return true
		}
	}
	return false
}

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

	// Persist L1 beliefs between requests; only initialize if empty to support streaming and fragmented packets
	if len(state.L1Beliefs) == 0 {
		state.L1Beliefs = []float64{GatewayConfig.L1BaselineSafe, GatewayConfig.L1BaselineSusp, GatewayConfig.L1BaselineMal}
	}

	for _, tok := range tokens {
		_, vfe := state.UpdateL1Perception(&l1Action, tok)
		totalL1VFE += vfe
	}

	avgL1VFE := 0.0
	if len(tokens) > 0 {
		avgL1VFE = totalL1VFE / float64(len(tokens))
	}

	textToScan := string(body)
	var fullTextToScan string

	if isAgentRoute {
		// 1. Detect and parse Agent Tool Call (JSON-RPC or standard)
		var agentPayload AgentPayload
		if err := json.Unmarshal(body, &agentPayload); err == nil {
			var sb strings.Builder
			if agentPayload.Method != "" {
				sb.WriteString(agentPayload.Method)
				sb.WriteString(" ")
			}
			if agentPayload.Tool != "" {
				sb.WriteString(agentPayload.Tool)
				sb.WriteString(" ")
			}
			if agentPayload.Params.Name != "" {
				sb.WriteString(agentPayload.Params.Name)
				sb.WriteString(" ")
			}
			if len(agentPayload.Params.Arguments) > 0 {
				sb.Write(agentPayload.Params.Arguments)
				sb.WriteString(" ")
			}
			if len(agentPayload.Args) > 0 {
				sb.Write(agentPayload.Args)
				sb.WriteString(" ")
			}
			fullTextToScan = sb.String()
		} else {
			fullTextToScan = string(body)
		}

		// 2. Dynamic Suffix Slicing (The Agent Shield)
		prevText := state.LastProcessedText

		if prevText != "" && strings.HasPrefix(fullTextToScan, prevText) {
			textToScan = fullTextToScan[len(prevText):]
		} else {
			textToScan = fullTextToScan
		}
	} else {
		// 1. Detect and parse Chat Completion
		var chatReq struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(body, &chatReq); err == nil && len(chatReq.Messages) > 0 {
			historyMatched := false
			if len(chatReq.Messages) > 1 {
				h := sha256.New()
				for i := 0; i < len(chatReq.Messages)-1; i++ {
					h.Write([]byte(chatReq.Messages[i].Role + ":" + chatReq.Messages[i].Content))
				}
				historyHash := hex.EncodeToString(h.Sum(nil))
				if state.ProcessedHistoryHash == historyHash {
					historyMatched = true
				}
			} else {
				if state.ProcessedHistoryHash == "" {
					historyMatched = true
				}
			}

			if historyMatched {
				// History matches approved log; scan only latest message to avoid VFE history loop spikes
				textToScan = chatReq.Messages[len(chatReq.Messages)-1].Content
			} else {
				// History has been tampered/modified or is a new session; scan entire chat message history
				var sb strings.Builder
				for _, msg := range chatReq.Messages {
					sb.WriteString(msg.Content)
					sb.WriteString(" ")
				}
				textToScan = sb.String()
			}
		}
		fullTextToScan = textToScan
	}



	var hasPII bool
	if state.Theta < 4.5 {
		if isEntityEnabled("US_SSN") && ssnRegex.MatchString(textToScan) {
			hasPII = true
		} else if isEntityEnabled("CREDIT_CARD") && ccRegex.MatchString(textToScan) {
			hasPII = true
		} else if isEntityEnabled("EMAIL_ADDRESS") && emailRegex.MatchString(textToScan) {
			hasPII = true
		} else if isEntityEnabled("PHONE_NUMBER") && phoneRegex.MatchString(textToScan) {
			hasPII = true
		} else if isEntityEnabled("LOCATION") && addrRegex.MatchString(textToScan) {
			hasPII = true
		}
	}

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

	state.IsLastRequestPII = hasPII

	if hasInjection {
		avgL1VFE = 4.2
	} else if hasPII {
		avgL1VFE = 2.5
	}

	state.HistoryL1VFE = append(state.HistoryL1VFE, avgL1VFE)

	var retVal int = OBS_READ

	// Bottom-up Surprise Mapping:
	// If syntactic surprise (VFE) is high, map to appropriate L2 observation
	if avgL1VFE > 2.0 {
		if hasPII || hasInjection {
			retVal = OBS_INPUT_ERROR
		} else {
			retVal = OBS_STRUCTURE_SHIFT
		}
	} else if isAgentRoute {
		// Heuristics fallback for agent actions (e.g. dangerous command keywords)
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
					retVal = OBS_STRUCTURE_SHIFT
					break
				}
			}
		}
	}

	if isAgentRoute {
		state.LastProcessedText = fullTextToScan
		state.LastProcessedTextTime = time.Now()
	}

	return retVal
}

// checkRateLimit implements sliding window rate limiting per session
func checkRateLimit(sessionID string) bool {
	if redisClient != nil {
		key := fmt.Sprintf("ratelimit:%s", sessionID)
		nowNano := time.Now().UnixNano()
		windowStart := nowNano - int64(2*time.Second)

		pipe := redisClient.TxPipeline()
		pipe.ZRemRangeByScore(redisCtx, key, "0", fmt.Sprintf("%d", windowStart))
		pipe.ZAdd(redisCtx, key, redis.Z{Score: float64(nowNano), Member: nowNano})
		pipe.ZCard(redisCtx, key)
		pipe.Expire(redisCtx, key, 5*time.Second)

		cmds, err := pipe.Exec(redisCtx)
		if err == nil && len(cmds) >= 3 {
			if countCmd, ok := cmds[2].(*redis.IntCmd); ok {
				count, _ := countCmd.Result()
				return count <= 15
			}
		}
	}

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

type PresidioResponse struct {
	Start      int     `json:"start"`
	End        int     `json:"end"`
	EntityType string  `json:"entity_type"`
	Score      float64 `json:"score"`
}

// RedactPII replaces PII patterns in the request body with unique placeholder tokens.
// If triggerNLP is true and the DLP provider is set to "presidio", it also scans via Microsoft Presidio sidecar.
func RedactPII(body []byte, triggerNLP bool) ([]byte, map[string]string) {
	if len(body) == 0 {
		return body, nil
	}

	// 1. Run regex-based redaction on the entire body first
	redactedBody, rehydrateMap := runRegexRedaction(body)

	// 2. Run Presidio NLP redaction on the user message if triggered
	if triggerNLP && GatewayConfig.DLPProvider == "presidio" {
		redactedBody, rehydrateMap = runPresidioRedaction(redactedBody, rehydrateMap)
	}

	return redactedBody, rehydrateMap
}

func runRegexRedaction(body []byte) ([]byte, map[string]string) {
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

	if isEntityEnabled("US_SSN") {
		replaceFunc(ssnRegex, "REDACTED_SSN")
	}
	if isEntityEnabled("CREDIT_CARD") {
		replaceFunc(ccRegex, "REDACTED_CC")
	}
	if isEntityEnabled("EMAIL_ADDRESS") {
		replaceFunc(emailRegex, "REDACTED_EMAIL")
	}
	if isEntityEnabled("PHONE_NUMBER") {
		replaceFunc(phoneRegex, "REDACTED_PHONE")
	}
	if isEntityEnabled("LOCATION") {
		replaceFunc(addrRegex, "REDACTED_ADDRESS")
	}

	return []byte(text), rehydrateMap
}

func runPresidioRedaction(body []byte, rehydrateMap map[string]string) ([]byte, map[string]string) {
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		logSecurityAuditEvent("siem-dlp-fail", "", "dlp_sidecar", "MONITOR", "DLP_PARSE_FAIL", 0.0, "ALLOW", false)
		return body, rehydrateMap
	}

	if len(req.Messages) == 0 {
		return body, rehydrateMap
	}

	lastIdx := len(req.Messages) - 1
	originalContent := req.Messages[lastIdx].Content
	if originalContent == "" {
		return body, rehydrateMap
	}

	// Call Presidio sidecar
	redactedContent, updatedMap, err := callPresidioSidecar(originalContent, rehydrateMap)
	if err != nil {
		// Fail-open: log error, raise SIEM alert, and return original body
		// Raise SIEM alert
		newTxID := "siem-dlp-" + fmt.Sprintf("%d", time.Now().UnixNano())
		logSecurityAuditEvent(newTxID, "", "dlp_sidecar", "MONITOR", "DLP_SIDE_FAIL", 0.0, "ALLOW", false)
		return body, rehydrateMap
	}

	req.Messages[lastIdx].Content = redactedContent

	newBody, err := json.Marshal(req)
	if err != nil {
		return body, rehydrateMap
	}

	return newBody, updatedMap
}

func callPresidioSidecar(text string, rehydrateMap map[string]string) (string, map[string]string, error) {
	endpoint := GatewayConfig.DLPEndpoint
	if endpoint == "" {
		endpoint = "http://aiaiai_dlp_sidecar:5001"
	}
	url := endpoint
	if !strings.HasSuffix(endpoint, "/analyze") {
		url = fmt.Sprintf("%s/analyze", endpoint)
	}

	entitiesList := []string{"PERSON", "LOCATION", "ORGANIZATION", "DATE_TIME"}
	if GatewayConfig.DLPPresidioEntities != "" {
		parts := strings.Split(GatewayConfig.DLPPresidioEntities, ",")
		var cleaned []string
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				cleaned = append(cleaned, trimmed)
			}
		}
		if len(cleaned) > 0 {
			entitiesList = cleaned
		}
	}

	reqPayload := map[string]interface{}{
		"text":     text,
		"language": "en",
		"entities": entitiesList,
	}

	jsonBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return text, rehydrateMap, err
	}

	// Create client with 2000ms timeout to handle cold-start NLP model loading
	client := &http.Client{
		Timeout: 2000 * time.Millisecond,
	}

	resp, err := client.Post(url, "application/json", strings.NewReader(string(jsonBytes)))
	if err != nil {
		return text, rehydrateMap, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return text, rehydrateMap, fmt.Errorf("sidecar returned status %d", resp.StatusCode)
	}

	var results []PresidioResponse
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return text, rehydrateMap, err
	}

	// Sort results by Start descending to redact from right to left
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].Start < results[j].Start {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	counter := len(rehydrateMap) + 1
	runes := []rune(text)

	for _, res := range results {
		if res.Start < 0 || res.End > len(runes) || res.Start >= res.End {
			continue
		}
		originalStr := string(runes[res.Start:res.End])
		placeholder := fmt.Sprintf("[REDACTED_%s_%d]", res.EntityType, counter)
		counter++

		rehydrateMap[placeholder] = originalStr

		prefix := runes[:res.Start]
		suffix := runes[res.End:]
		runes = append(append([]rune{}, prefix...), append([]rune(placeholder), suffix...)...)
	}

	return string(runes), rehydrateMap, nil
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
