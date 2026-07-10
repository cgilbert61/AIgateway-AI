import os
import time
import json
import select
import psycopg2
import redis
import requests
import math
import numpy as np
import threading
from concurrent.futures import ThreadPoolExecutor
from psycopg2.pool import ThreadedConnectionPool
from flask import Flask, request, jsonify
from pydantic import BaseModel, Field, field_validator, ValidationError
from typing import List
from active_engine import Layer2Engine

class Layer3MatrixInputs(BaseModel):
    a2: List[List[float]] = Field(..., description="Likelihood matrix A2, shape 3x3")
    b2: List[List[List[float]]] = Field(..., description="Transition matrix B2, shape 3x3x3")
    c2: List[float] = Field(..., description="Prior preferences C2, length 3")

    @field_validator("a2")
    @classmethod
    def validate_a2(cls, v: List[List[float]]) -> List[List[float]]:
        arr = np.array(v, dtype=float)
        if arr.shape != (3, 3):
            raise ValueError(f"A2 must have shape 3x3, got {arr.shape}")
        if np.any(arr < 0):
            raise ValueError("All values in A2 must be non-negative")
        # Check column stochasticity
        col_sums = arr.sum(axis=0)
        for col_idx, col_sum in enumerate(col_sums):
            if not np.isclose(col_sum, 1.0, rtol=1e-5):
                raise ValueError(f"Offending column sum in A2 at index {col_idx}: {col_sum:.6f} (must sum to 1.0 +- 1e-5)")
        return v

    @field_validator("b2")
    @classmethod
    def validate_b2(cls, v: List[List[List[float]]]) -> List[List[List[float]]]:
        arr = np.array(v, dtype=float)
        if arr.shape != (3, 3, 3):
            raise ValueError(f"B2 must have shape 3x3x3, got {arr.shape}")
        if np.any(arr < 0):
            raise ValueError("All values in B2 must be non-negative")
        # Check column stochasticity for each action
        for act in range(3):
            col_sums = arr[:, :, act].sum(axis=0)
            for col_idx, col_sum in enumerate(col_sums):
                if not np.isclose(col_sum, 1.0, rtol=1e-5):
                    raise ValueError(f"Offending column sum in B2 (action {act}, column {col_idx}): {col_sum:.6f} (must sum to 1.0 +- 1e-5)")
        return v

    @field_validator("c2")
    @classmethod
    def validate_c2(cls, v: List[float]) -> List[float]:
        arr = np.array(v, dtype=float)
        if arr.shape != (3,):
            raise ValueError(f"C2 must have length 3, got {arr.shape}")
        if np.any(np.isnan(arr)) or np.any(np.isinf(arr)):
            raise ValueError("NaN or Inf values are not allowed in C2")
        return v

# Global Cache of Layer 2 Engines per Session
session_engines = {}

db_pool = None
redis_client = None

def init_db_pool():
    global db_pool
    db_url = os.environ.get("DATABASE_URL", "postgresql://user:password@postgres_db:5432/postgres?sslmode=disable")
    while True:
        try:
            db_pool = ThreadedConnectionPool(minconn=5, maxconn=100, dsn=db_url)
            print("[Sidecar] Database connection pool initialized successfully.")
            break
        except Exception as e:
            print(f"[Sidecar] Connection pool init failed, retrying: {e}")
            time.sleep(2)

def init_redis_client():
    global redis_client
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        if not redis_url.startswith("redis://"):
            redis_url = f"redis://{redis_url}"
        try:
            redis_client = redis.Redis.from_url(redis_url, socket_timeout=5)
            print("[Sidecar] Redis client initialized successfully.")
        except Exception as e:
            print(f"[Sidecar] Redis client initialization failed: {e}")

def get_db_connection():
    db_url = os.environ.get("DATABASE_URL", "postgresql://user:password@postgres_db:5432/postgres?sslmode=disable")
    while True:
        try:
            conn = psycopg2.connect(db_url)
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            return conn
        except Exception as e:
            print(f"[Sidecar] DB connection failed, retrying in 2 seconds: {e}")
            time.sleep(2)

def get_l3_gamma():
    try:
        config_path = os.environ.get("GATEWAY_CONFIG_PATH", "/app/config/gateway_config.json")
        if os.path.exists(config_path):
            with open(config_path) as f:
                data = json.load(f)
            return float(data.get("l3_precision_gamma", 15.0))
    except Exception as e:
        print(f"[Sidecar] Error reading config for L3 gamma: {e}")
    return 15.0

def handle_notification(event_or_uuid):
    if not db_pool:
        print("[Sidecar Error] DB connection pool not initialized.")
        return

    conn = db_pool.getconn()
    try:
        cur = conn.cursor()
        
        if isinstance(event_or_uuid, dict):
            session_id = event_or_uuid.get("session_id")
            obs_vector = event_or_uuid.get("observation_vector")
            vfe_score = event_or_uuid.get("vfe_score")
            is_blocked = event_or_uuid.get("is_blocked")
        else:
            # 1. Targeted indexed read to fetch the transaction payload
            cur.execute(
                "SELECT session_id, observation_vector, vfe_score, is_blocked FROM runtime_inference_state WHERE transaction_id = %s",
                (event_or_uuid,)
            )
            row = cur.fetchone()
            if not row:
                return
            session_id, obs_vector, vfe_score, is_blocked = row

        if obs_vector is None or session_id is None:
            return
            
        obs_1 = obs_vector[0] # Layer 2 compliance observation index (0-3)

        # 2. Fetch session matrices
        cur.execute(
            """SELECT layer1_matrix_a, layer1_matrix_b, 
                      layer2_matrix_a, layer2_matrix_b, layer2_matrix_c
               FROM agent_profile_matrices WHERE session_id = %s""",
            (session_id,)
        )
        matrix_row = cur.fetchone()
        if not matrix_row:
            print(f"[Sidecar] Session matrices not found for session {session_id}.")
            return

        raw_a1, raw_b1, raw_a2, raw_b2, raw_c2 = matrix_row

        # 2.5. Pydantic validation of Layer 3 active inference matrices
        try:
            Layer3MatrixInputs(a2=raw_a2, b2=raw_b2, c2=raw_c2)
        except ValidationError as e:
            print(f"[Sidecar Error] Validation failed for session {session_id} matrices: {e}")
            return

        # 3. Load or create Layer 3 engine (mapped from Layer2Engine class)
        engine = session_engines.get(session_id)
        if not engine:
            engine = Layer2Engine(raw_a2, raw_b2, raw_c2)
            session_engines[session_id] = engine

        # Map Layer 2 outcomes to Layer 3 observations:
        # L2 Action = BLOCK or high L2 VFE -> Exfil (2)
        # L2 Obs = Shift/Error or L2 VFE elevated -> Neutral (1)
        # Otherwise -> Safe (0)
        obs_3 = 0
        if is_blocked or vfe_score > 3.0:
            obs_3 = 2
        elif obs_1 in (1, 2) or vfe_score > 1.5:
            obs_3 = 1

        # 4. Execute Layer 3 Perception
        prev_action = engine.history_actions[-1] if engine.history_actions else None
        qs, vfe_3 = engine.update_perception(prev_action, obs_3)

        # 5. Execute Layer 3 Action Selection (modulates Layer 2 prior distribution parameters)
        decided_action, q_pi = engine.select_action(qs, gamma=get_l3_gamma())

        # Load defaults for Layer 2 matrices (saved as layer1 in config and DB for compatibility)
        default_a1, default_b1 = get_default_layer1_matrices()

        updated_a1, updated_b1 = engine.adjust_layer1_matrices(decided_action, default_a1, default_b1)

        # 6. Save modified matrices back to PostgreSQL only if the action changed (or first time)
        if prev_action is None or prev_action != decided_action:
            cur.execute(
                """UPDATE agent_profile_matrices 
                   SET layer1_matrix_a = %s, layer1_matrix_b = %s 
                   WHERE session_id = %s""",
                (json.dumps(updated_a1), json.dumps(updated_b1), session_id)
            )
            conn.commit()

        print(f"[Sidecar] Processed Layer 3 for Session {session_id}: L3 Obs {obs_3}, L3 Intent State {np_argmax_name(qs)}, Action {decided_action_name(decided_action)}, VFE: {vfe_3:.6f}")

        # 7. Notify Go Gateway to clear its matrix cache for this session
        notify_gateway_reload(session_id, qs.tolist(), decided_action, vfe_3, updated_a1, updated_b1)

    except Exception as e:
        print(f"[Sidecar Error] Error processing transaction {tx_uuid}: {e}")
        try:
            conn.rollback()
        except:
            pass
    finally:
        db_pool.putconn(conn)

def np_argmax_name(qs):
    idx = int(qs.argmax())
    return ["SafeIntent", "NeutralIntent", "ExfilIntent"][idx]

def decided_action_name(act):
    return ["SetPriorSafe", "SetPriorNeutral", "SetPriorExfil"][act]

def get_default_layer1_matrices():
    config_path = "/app/config/default_matrices.json"
    if not os.path.exists(config_path):
        config_path = "../config/default_matrices.json"
    with open(config_path) as f:
        data = json.load(f)
    return data["layer1_matrix_a"], data["layer1_matrix_b"]

def notify_gateway_reload(session_id, l2_beliefs, l2_action, l3_vfe, updated_a1=None, updated_b1=None):
    global redis_client
    payload = {
        "session_id": session_id,
        "l2_beliefs": l2_beliefs,
        "l2_action": int(l2_action),
        "l3_vfe": float(l3_vfe),
        "layer1_matrix_a": updated_a1,
        "layer1_matrix_b": updated_b1
    }
    if redis_client:
        try:
            redis_client.publish("active_inference:reloads", json.dumps(payload))
            return
        except Exception as e:
            print(f"[Sidecar Redis PubSub Error] Failed to publish reload config, falling back to HTTP: {e}")

    gateway_url = os.environ.get("GATEWAY_URL", "http://gateway_proxy:1163")
    try:
        resp = requests.post(
            f"{gateway_url}/config/reload", 
            json=payload, 
            headers={"Content-Type": "application/json"},
            timeout=2
        )
        if resp.status_code != 200:
            print(f"[Sidecar] Gateway reload HTTP callback failed with status: {resp.status_code}")
    except Exception as e:
        print(f"[Sidecar] Failed to connect to Gateway reload HTTP callback: {e}")

# Flask validation API endpoint
app_api = Flask("sidecar-api")

@app_api.route("/api/inference", methods=["POST"])
def api_inference():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON payload"}), 400
        
        a2 = data.get("a2")
        b2 = data.get("b2")
        c2 = data.get("c2")
        
        # Enforce rigid Pydantic validation
        Layer3MatrixInputs(a2=a2, b2=b2, c2=c2)
        
        return jsonify({"status": "SUCCESS", "message": "Validation passed."}), 200
    except ValidationError as e:
        errors = e.errors()
        err_msg = errors[0]["msg"] if errors else str(e)
        if err_msg.startswith("Value error, "):
            err_msg = err_msg[len("Value error, "):]
        return jsonify({"status": "INVALID", "error": err_msg}), 422
    except Exception as e:
        return jsonify({"status": "ERROR", "error": str(e)}), 500

def run_flask():
    print("[Sidecar] Starting HTTP validation API on port 5001...")
    # Bind to port 5001 as specified in deployment config
    app_api.run(host="0.0.0.0", port=5001, debug=False, use_reloader=False)

def run_redis_subscriber(executor):
    global redis_client
    if not redis_client:
        print("[Sidecar] Redis client not initialized. Skipping Redis Pub/Sub subscriber.")
        return
        
    pubsub = redis_client.pubsub()
    pubsub.subscribe("active_inference:transactions")
    print("[Sidecar] Subscribed to Redis Pub/Sub channel: active_inference:transactions")
    
    while True:
        try:
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message:
                payload = json.loads(message["data"])
                executor.submit(handle_notification, payload)
        except redis.ConnectionError as e:
            print(f"[Sidecar Error] Lost Redis connection, retrying in 2 seconds: {e}")
            time.sleep(2)
            try:
                pubsub = redis_client.pubsub()
                pubsub.subscribe("active_inference:transactions")
            except:
                pass
        except Exception as e:
            print(f"[Sidecar Error] Error in Redis subscriber loop: {e}")
            time.sleep(1)

def main():
    # 0. Initialize threaded database connection pool & Redis client
    init_db_pool()
    init_redis_client()

    # 1. Start Flask API server in a background daemon thread
    t = threading.Thread(target=run_flask, daemon=True)
    t.start()

    # 2. Initialize thread pool executor for processing notifications concurrently
    executor = ThreadPoolExecutor(max_workers=80)

    # 3. Start Redis subscriber in a background thread if Redis is configured
    if os.environ.get("REDIS_URL"):
        t_redis = threading.Thread(target=run_redis_subscriber, args=(executor,), daemon=True)
        t_redis.start()

    print("[Sidecar] Starting PostgreSQL notification listener loop...")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("LISTEN runtime_state_channel;")
    print("[Sidecar] Subscribed to PostgreSQL channel: runtime_state_channel")

    while True:
        try:
            if select.select([conn], [], [], 5) == ([], [], []):
                # Timeout, keepalive ping to check connection
                cur.execute("SELECT 1;")
            else:
                conn.poll()
                while conn.notifies:
                    notify = conn.notifies.pop(0)
                    tx_uuid = notify.payload
                    # Submit notification to thread pool to execute in parallel
                    executor.submit(handle_notification, tx_uuid)
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            print(f"[Sidecar] Lost connection to database, reconnecting: {e}")
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("LISTEN runtime_state_channel;")
        except Exception as e:
            print(f"[Sidecar] Error in listener loop: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
