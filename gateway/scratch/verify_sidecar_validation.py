import requests
import json

sidecar_url = "http://localhost:5001/api/inference"

# 1. Test clean validation
clean_payload = {
    "a2": [
        [0.9, 0.05, 0.05],
        [0.05, 0.9, 0.05],
        [0.05, 0.05, 0.9]
    ],
    "b2": [
        # next_state = 0
        [
            [0.90, 0.40, 0.10], # prev_state 0: action 0, 1, 2
            [0.15, 0.10, 0.05], # prev_state 1: action 0, 1, 2
            [0.05, 0.05, 0.02]  # prev_state 2: action 0, 1, 2
        ],
        # next_state = 1
        [
            [0.08, 0.55, 0.10],
            [0.80, 0.85, 0.15],
            [0.15, 0.25, 0.08]
        ],
        # next_state = 2
        [
            [0.02, 0.05, 0.80],
            [0.05, 0.05, 0.80],
            [0.80, 0.70, 0.90]
        ]
    ],
    "c2": [0.90, 0.08, 0.02]
}

print("Running test: Clean Matrix Validation")
try:
    r = requests.post(sidecar_url, json=clean_payload, timeout=2)
    print(f"Status Code: {r.status_code}")
    print(f"Response: {r.text}\n")
except Exception as e:
    print(f"Connection failed: {e}\n")

# 2. Test invalid A2 sum
invalid_a2_payload = {
    "a2": [
        [0.8, 0.05, 0.05], # first column sums to 0.9 instead of 1.0
        [0.05, 0.9, 0.05],
        [0.05, 0.05, 0.9]
    ],
    "b2": clean_payload["b2"],
    "c2": clean_payload["c2"]
}

print("Running test: Invalid A2 Column Sum")
try:
    r = requests.post(sidecar_url, json=invalid_a2_payload, timeout=2)
    print(f"Status Code: {r.status_code}")
    print(f"Response: {r.text}\n")
except Exception as e:
    print(f"Connection failed: {e}\n")

# 3. Test negative value
negative_payload = {
    "a2": [
        [-0.1, 0.5, 0.6], # negative value in A2
        [0.1, 0.5, 0.4],
        [1.0, 0.0, 0.0]
    ],
    "b2": clean_payload["b2"],
    "c2": clean_payload["c2"]
}

print("Running test: Negative Value Validation")
try:
    r = requests.post(sidecar_url, json=negative_payload, timeout=2)
    print(f"Status Code: {r.status_code}")
    print(f"Response: {r.text}\n")
except Exception as e:
    print(f"Connection failed: {e}\n")
