-- Ephemeral transactional table bypassing the Write-Ahead Log completely
CREATE UNLOGGED TABLE runtime_inference_state (
    transaction_id UUID PRIMARY KEY,
    session_id UUID NOT NULL,
    observation_vector INT[] NOT NULL, 
    vfe_score DOUBLE PRECISION,         
    vfe_score_l1 DOUBLE PRECISION,
    vfe_score_l3 DOUBLE PRECISION,
    is_blocked BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexing for high-frequency sliding window memory sweeping operations
CREATE INDEX IF NOT EXISTS idx_runtime_inference_state_updated 
ON runtime_inference_state (updated_at);

-- Hierarchical Matrix Repository for Deep Temporal Active Inference parameters
CREATE TABLE agent_profile_matrices (
    session_id UUID PRIMARY KEY,
    layer1_matrix_a JSONB NOT NULL, -- Layer 1 Likelihoods (Syntax mapping)
    layer1_matrix_b JSONB NOT NULL, -- Layer 1 Transitions
    layer2_matrix_a JSONB NOT NULL, -- Layer 2 Semantics (Intent-to-Prior mapping)
    layer2_matrix_b JSONB NOT NULL, -- Layer 2 Intent Transitions
    layer2_matrix_c JSONB NOT NULL, -- Layer 2 Goal Preferences
    threshold_theta DOUBLE PRECISION NOT NULL,
    calibrated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Trigger function for real-time pub/sub notification bypassing payload size restrictions
CREATE OR REPLACE FUNCTION notify_runtime_inference_state()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('runtime_state_channel', NEW.transaction_id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Bind trigger to run on every insert to the runtime state table
CREATE TRIGGER trg_notify_runtime_inference_state
AFTER INSERT ON runtime_inference_state
FOR EACH ROW
EXECUTE FUNCTION notify_runtime_inference_state();

-- Session quarantine registry for manual accept/reject workflow
CREATE TABLE IF NOT EXISTS session_quarantine (
    session_id VARCHAR(255) PRIMARY KEY,
    status VARCHAR(30) DEFAULT 'QUARANTINED',
    reason VARCHAR(255) DEFAULT '',
    quarantined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    decided_at TIMESTAMP WITH TIME ZONE
);

-- Configurable SIEM pipeline credentials
CREATE TABLE IF NOT EXISTS siem_config (
    provider VARCHAR(50) PRIMARY KEY,
    endpoint_url VARCHAR(255) NOT NULL,
    auth_token VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT FALSE
);

