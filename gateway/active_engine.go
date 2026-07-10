

package main

import (
	"math"
	"sync"
	"time"
)

// Layer 1 State Space Constants
const (
	STATE_SAFE       = 0
	STATE_SUSPICIOUS = 1
	STATE_MALICIOUS  = 2
)

// Layer 1 Observation Channels
const (
	OBS_READ            = 0
	OBS_STRUCTURE_SHIFT = 1
	OBS_INPUT_ERROR     = 2
	OBS_INGRESS_FLOOD   = 3
)

// Layer 1 Action Constants
const (
	ACTION_ALLOW   = 0
	ACTION_MONITOR = 1
	ACTION_BLOCK   = 2
)

// ActiveInfState holds the running parameters and history of a single session
type ActiveInfState struct {
	sync.Mutex     `json:"-"`
	PriorBeliefs   []float64     `json:"prior_beliefs"`
	A              [][]float64   `json:"a"`
	B              [][][]float64 `json:"b"`
	CurrentAction  int           `json:"current_action"`
	CurrentObs     int           `json:"current_obs"`
	HistoryVFE     []float64     `json:"history_vfe"`
	HistoryBeliefs [][]float64   `json:"history_beliefs"`
	HistoryObs     []int         `json:"history_obs"`
	HistoryAction  []int         `json:"history_action"`
	Ticks          int           `json:"ticks"`
	L2Beliefs      []float64     `json:"l2_beliefs"` // Maps to L3 beliefs in 3-layer schema
	L2Action       int           `json:"l2_action"`  // Maps to L3 action in 3-layer schema
	HistoryPayloads []PayloadDetail `json:"history_payloads"`
	Theta           float64         `json:"threshold_theta"`
	SessionUUID     string          `json:"session_uuid"`
	LastRequestTime time.Time       `json:"last_request_time"`
	LeakyVFE        float64         `json:"leaky_vfe"`

	// Deduplication fields
	LastRequestHash   string    `json:"-"`
	LastResponseBytes []byte    `json:"-"`
	LastResponseCode  int       `json:"-"`
	ConsecutiveDuplicatesCount int `json:"-"`

	// Layer 1 Syntactic parameters (3-layer hierarchical integration)
	L1Beliefs    []float64     `json:"l1_beliefs"`
	A1           [][]float64   `json:"a1"`
	B1           [][][]float64 `json:"b1"`
	HistoryL1VFE []float64     `json:"history_l1_vfe"`
	HistoryL3VFE []float64     `json:"history_l3_vfe"`
}

type PayloadDetail struct {
	TxID               string `json:"tx_id"`
	RawRequest         string `json:"raw_request"`
	TranslatedRequest  string `json:"translated_request"`
	RawResponse        string `json:"raw_response"`
	TranslatedResponse string `json:"translated_response"`
}

// NewActiveInfState initializes the Layer 1 and Layer 2 state space model with normalized matrices
func NewActiveInfState(rawA [][]float64, rawB [][][]float64) *ActiveInfState {
	A := normalizeA(rawA)
	B := normalizeB(rawB)

	priorBeliefs := []float64{
		GatewayConfig.L1BaselineSafe,
		GatewayConfig.L1BaselineSusp,
		GatewayConfig.L1BaselineMal,
	}
	if priorBeliefs[0] == 0 && priorBeliefs[1] == 0 && priorBeliefs[2] == 0 {
		priorBeliefs = []float64{0.95, 0.04, 0.01}
	}
	l1Beliefs := []float64{priorBeliefs[0], priorBeliefs[1], priorBeliefs[2]}

	// Default L1 matrices
	rawA1 := [][]float64{
		{0.85, 0.10, 0.05}, // OBS_L1_ALPHANUMERIC
		{0.05, 0.80, 0.05}, // OBS_L1_SYNTAX_CHAR
		{0.05, 0.05, 0.70}, // OBS_L1_SPECIAL_CHAR
		{0.05, 0.05, 0.20}, // OBS_L1_CONTROL_CHAR
	}
	rawB1 := [][][]float64{
		// Action 0 (Accept)
		{
			{0.90, 0.15, 0.05},
			{0.08, 0.80, 0.15},
			{0.02, 0.05, 0.80},
		},
		// Action 1 (Buffer)
		{
			{0.40, 0.10, 0.05},
			{0.55, 0.85, 0.25},
			{0.05, 0.05, 0.70},
		},
		// Action 2 (Drop)
		{
			{0.10, 0.05, 0.02},
			{0.10, 0.15, 0.08},
			{0.80, 0.80, 0.90},
		},
	}

	A1 := normalizeA(rawA1)
	B1 := normalizeB(rawB1)

	return &ActiveInfState{
		PriorBeliefs:   priorBeliefs,
		A:              A,
		B:              B,
		CurrentAction:  ACTION_ALLOW,
		CurrentObs:     OBS_READ,
		HistoryVFE:     []float64{0.0},
		HistoryBeliefs: [][]float64{priorBeliefs},
		HistoryObs:     []int{OBS_READ},
		HistoryAction:  []int{ACTION_ALLOW},
		Ticks:          0,
		L2Beliefs:      []float64{0.90, 0.08, 0.02}, // default L3 starting beliefs
		L2Action:       0,
		HistoryPayloads: []PayloadDetail{},
		LastRequestTime: time.Now(),

		// L1 elements
		L1Beliefs:    l1Beliefs,
		A1:           A1,
		B1:           B1,
		HistoryL1VFE: []float64{0.0},
		HistoryL3VFE: []float64{0.0},
	}
}

// normalizeA column-normalizes the A likelihood matrix: sum_o A[o][s] = 1.0
func normalizeA(rawA [][]float64) [][]float64 {
	A := make([][]float64, 4)
	for i := range A {
		A[i] = make([]float64, 3)
	}

	for col := 0; col < 3; col++ {
		sum := 0.0
		for row := 0; row < 4; row++ {
			sum += rawA[row][col]
		}
		for row := 0; row < 4; row++ {
			if sum > 0 {
				A[row][col] = rawA[row][col] / sum
			} else {
				A[row][col] = 1.0 / 4.0
			}
		}
	}
	return A
}

// normalizeB column-normalizes the B transition matrix: sum_s_next B[s_next][s_prev][action] = 1.0
func normalizeB(rawB [][][]float64) [][][]float64 {
	B := make([][][]float64, 3)
	for i := range B {
		B[i] = make([][]float64, 3)
		for j := range B[i] {
			B[i][j] = make([]float64, 3)
		}
	}

	for action := 0; action < 3; action++ {
		for col := 0; col < 3; col++ {
			sum := 0.0
			for row := 0; row < 3; row++ {
				sum += rawB[row][col][action]
			}
			for row := 0; row < 3; row++ {
				if sum > 0 {
					B[row][col][action] = rawB[row][col][action] / sum
				} else {
					B[row][col][action] = 1.0 / 3.0
				}
			}
		}
	}
	return B
}

// UpdatePerception performs the Bayesian update given the observation and action, returning updated beliefs and Variational Free Energy (VFE)
func (s *ActiveInfState) UpdatePerception(prevAction *int, observation int) ([]float64, float64) {
	baseline := []float64{
		GatewayConfig.L1BaselineSafe,
		GatewayConfig.L1BaselineSusp,
		GatewayConfig.L1BaselineMal,
	}
	if baseline[0] == 0 && baseline[1] == 0 && baseline[2] == 0 {
		baseline = []float64{0.95, 0.04, 0.01}
	}
	if !s.LastRequestTime.IsZero() {
		elapsed := time.Since(s.LastRequestTime).Seconds()
		decay := 1.0 - math.Exp(-elapsed*GatewayConfig.L2DecayRate)
		for i := 0; i < 3; i++ {
			s.PriorBeliefs[i] = (1.0-decay)*s.PriorBeliefs[i] + decay*baseline[i]
		}
		// Decay the cumulative LeakyVFE
		s.LeakyVFE = s.LeakyVFE * math.Exp(-elapsed*GatewayConfig.L2DecayRate)
	}
	s.LastRequestTime = time.Now()

	// 1. Calculate prior beliefs over current state
	priorQS := make([]float64, 3)
	if prevAction == nil {
		copy(priorQS, s.PriorBeliefs)
	} else {
		act := *prevAction
		for i := 0; i < 3; i++ {
			sum := 0.0
			for j := 0; j < 3; j++ {
				sum += s.B[i][j][act] * s.PriorBeliefs[j]
			}
			priorQS[i] = sum
		}
	}

	// 2. Perform Bayesian update with observation
	unnormalized := make([]float64, 3)
	sumUnnormalized := 0.0
	for i := 0; i < 3; i++ {
		unnormalized[i] = s.A[observation][i] * priorQS[i]
		sumUnnormalized += unnormalized[i]
	}

	qs := make([]float64, 3)
	for i := 0; i < 3; i++ {
		if sumUnnormalized > 0 {
			qs[i] = unnormalized[i] / sumUnnormalized
		} else {
			qs[i] = priorQS[i]
		}
	}

	// 3. Compute Variational Free Energy (VFE)
	vfe := 0.0
	for i := 0; i < 3; i++ {
		if qs[i] > 0 {
			priorVal := priorQS[i]
			if priorVal <= 0 {
				priorVal = 1e-16
			}
			kl := qs[i] * (math.Log(qs[i]) - math.Log(priorVal))

			valA := s.A[observation][i]
			if valA <= 0 {
				valA = 1e-16
			}
			likelihoodTerm := qs[i] * math.Log(valA)

			vfe += kl - likelihoodTerm
		}
	}

	s.PriorBeliefs = qs
	s.Ticks++
	s.HistoryBeliefs = append(s.HistoryBeliefs, qs)
	s.HistoryObs = append(s.HistoryObs, observation)
	s.HistoryVFE = append(s.HistoryVFE, vfe)
	s.LeakyVFE += vfe
	s.PruneHistory()
	return qs, vfe
}

// SelectActionEFE calculates policy Expected Free Energy (EFE) and returns action probabilities
func (s *ActiveInfState) SelectActionEFE(qs []float64, gamma float64) ([]float64, []float64) {
	// Preferences C (log space) for observations: Read, StructureShift, InputError, IngressFlood
	C := []float64{3.0, 0.0, -2.0, -8.0}
	// Habit bias E for Actions: ALLOW, MONITOR, BLOCK
	E := []float64{0.95, 0.049, 0.001}

	efe := make([]float64, 3)
	for action := 0; action < 3; action++ {
		// Predict next state
		qsPred := make([]float64, 3)
		for i := 0; i < 3; i++ {
			sum := 0.0
			for j := 0; j < 3; j++ {
				sum += s.B[i][j][action] * qs[j]
			}
			qsPred[i] = sum
		}

		// Predict Expected Free Energy:
		// G(u) = sum_s qs_pred[s] * sum_o A[o][s] * (ln(A[o][s]) - C[o])
		g := 0.0
		for sIdx := 0; sIdx < 3; sIdx++ {
			for oIdx := 0; oIdx < 4; oIdx++ {
				valA := s.A[oIdx][sIdx]
				logA := 0.0
				if valA > 0 {
					logA = math.Log(valA)
				}
				g += qsPred[sIdx] * valA * (logA - C[oIdx])
			}
		}
		efe[action] = g
	}

	// Softmax to get q_pi: value = ln(E[a]) - gamma * G(a)
	logQPi := make([]float64, 3)
	maxVal := -math.MaxFloat64
	for action := 0; action < 3; action++ {
		logE := math.Log(E[action])
		val := logE - gamma*efe[action]
		logQPi[action] = val
		if val > maxVal {
			maxVal = val
		}
	}

	sumExp := 0.0
	qPi := make([]float64, 3)
	for action := 0; action < 3; action++ {
		qPi[action] = math.Exp(logQPi[action] - maxVal)
		sumExp += qPi[action]
	}

	for action := 0; action < 3; action++ {
		if sumExp > 0 {
			qPi[action] /= sumExp
		} else {
			qPi[action] = 1.0 / 3.0
		}
	}

	return qPi, efe
}

// UpdateMatrices updates the matrices A and B of the existing state in place, preserving beliefs and history
func (s *ActiveInfState) UpdateMatrices(rawA [][]float64, rawB [][][]float64) {
	s.A = normalizeA(rawA)
	s.B = normalizeB(rawB)
}

// UpdateL2State updates the cached Layer 2 semantic beliefs and action in the active state
func (s *ActiveInfState) UpdateL2State(beliefs []float64, action int) {
	if len(beliefs) == 3 {
		s.L2Beliefs = beliefs
	}
	s.L2Action = action
}

// UpdateL1Perception performs Layer 1 (Syntactic) perception updates, returning updated beliefs and syntactic VFE
func (s *ActiveInfState) UpdateL1Perception(prevAction *int, observation int) ([]float64, float64) {
	// 1. Calculate prior beliefs over current state
	priorQS := make([]float64, 3)
	if prevAction == nil {
		priorQS = []float64{0.95, 0.04, 0.01}
	} else {
		act := *prevAction
		for i := 0; i < 3; i++ {
			sum := 0.0
			for j := 0; j < 3; j++ {
				sum += s.B1[i][j][act] * s.L1Beliefs[j]
			}
			priorQS[i] = sum
		}
	}

	// 2. Perform Bayesian update with observation
	unnormalized := make([]float64, 3)
	sumUnnormalized := 0.0
	for i := 0; i < 3; i++ {
		unnormalized[i] = s.A1[observation][i] * priorQS[i]
		sumUnnormalized += unnormalized[i]
	}

	qs := make([]float64, 3)
	for i := 0; i < 3; i++ {
		if sumUnnormalized > 0 {
			qs[i] = unnormalized[i] / sumUnnormalized
		} else {
			qs[i] = priorQS[i]
		}
	}

	// 3. Compute Variational Free Energy (VFE)
	vfe := 0.0
	for i := 0; i < 3; i++ {
		if qs[i] > 0 {
			priorVal := priorQS[i]
			if priorVal <= 0 {
				priorVal = 1e-16
			}
			kl := qs[i] * (math.Log(qs[i]) - math.Log(priorVal))

			valA := s.A1[observation][i]
			if valA <= 0 {
				valA = 1e-16
			}
			vfe += kl - qs[i]*math.Log(valA)
		}
	}

	s.L1Beliefs = qs
	return qs, vfe
}

// UpdateL1Matrices allows in-place updates of L1 likelihood and transitions
func (s *ActiveInfState) UpdateL1Matrices(rawA1 [][]float64, rawB1 [][][]float64) {
	s.A1 = normalizeA1(rawA1)
	s.B1 = normalizeB1(rawB1)
}

func normalizeA1(rawA [][]float64) [][]float64 {
	A := make([][]float64, 4)
	for i := range A {
		A[i] = make([]float64, 3)
	}

	for col := 0; col < 3; col++ {
		sum := 0.0
		for row := 0; row < 4; row++ {
			sum += rawA[row][col]
		}
		for row := 0; row < 4; row++ {
			if sum > 0 {
				A[row][col] = rawA[row][col] / sum
			} else {
				A[row][col] = 1.0 / 4.0
			}
		}
	}
	return A
}

func normalizeB1(rawB [][][]float64) [][][]float64 {
	B := make([][][]float64, 3)
	for i := range B {
		B[i] = make([][]float64, 3)
		for j := range B[i] {
			B[i][j] = make([]float64, 3)
		}
	}

	for action := 0; action < 3; action++ {
		for col := 0; col < 3; col++ {
			sum := 0.0
			for row := 0; row < 3; row++ {
				sum += rawB[row][col][action]
			}
			for row := 0; row < 3; row++ {
				if sum > 0 {
					B[row][col][action] = rawB[row][col][action] / sum
				} else {
					B[row][col][action] = 1.0 / 3.0
				}
			}
		}
	}
	return B
}

func (s *ActiveInfState) CacheResponse(hash string, bytes []byte, code int) {
	if hash != s.LastRequestHash || time.Since(s.LastRequestTime) >= time.Duration(GatewayConfig.DeduplicateWindowMs)*time.Millisecond {
		s.ConsecutiveDuplicatesCount = 0
	}
	s.LastRequestHash = hash
	s.LastResponseBytes = bytes
	s.LastResponseCode = code
	s.LastRequestTime = time.Now()
}

func (s *ActiveInfState) PruneHistory() {
	const maxLen = 30
	if len(s.HistoryBeliefs) > maxLen {
		s.HistoryBeliefs = s.HistoryBeliefs[len(s.HistoryBeliefs)-maxLen:]
	}
	if len(s.HistoryObs) > maxLen {
		s.HistoryObs = s.HistoryObs[len(s.HistoryObs)-maxLen:]
	}
	if len(s.HistoryVFE) > maxLen {
		s.HistoryVFE = s.HistoryVFE[len(s.HistoryVFE)-maxLen:]
	}
	if len(s.HistoryAction) > maxLen {
		s.HistoryAction = s.HistoryAction[len(s.HistoryAction)-maxLen:]
	}
	if len(s.HistoryL1VFE) > maxLen {
		s.HistoryL1VFE = s.HistoryL1VFE[len(s.HistoryL1VFE)-maxLen:]
	}
	if len(s.HistoryL3VFE) > maxLen {
		s.HistoryL3VFE = s.HistoryL3VFE[len(s.HistoryL3VFE)-maxLen:]
	}
	if len(s.HistoryPayloads) > maxLen {
		s.HistoryPayloads = s.HistoryPayloads[len(s.HistoryPayloads)-maxLen:]
	}
}
