import requests
import json

base_url = "http://localhost:1173"

def run_test(name, url, headers, body):
    print(f"\n=================== Running test: {name} ===================")
    full_url = f"{base_url}{url}"
    headers["X-Trace-Flow"] = "true"
    try:
        r = requests.post(full_url, headers=headers, json=body, timeout=5)
        print(f"Status Code: {r.status_code}")
        try:
            res_json = r.json()
            if "_trace" in res_json:
                print(f"Trace returned successfully!")
                print(json.dumps(res_json["_trace"], indent=2))
            else:
                print("No _trace object found in response!")
                print(json.dumps(res_json, indent=2))
        except Exception as je:
            print(f"Failed to parse JSON response: {je}. Raw: {r.text}")
    except Exception as e:
        print(f"Request failed: {e}")

# Test 1: Clean Chat
run_test(
    "Clean Request", 
    "/v1/chat/completions",
    {}, 
    {"messages": [{"role": "user", "content": "Hello"}]}
)

# Test 2: OPA policy block
run_test(
    "OPA Policy Block", 
    "/v1/agent/action",
    {"X-Agent-Key": "agent-retro-sysop", "X-User-Role": "anonymous"}, 
    {"tool": "execute_bash_command", "args": {"command": "rm -rf /"}}
)

# Test 3: PII block
run_test(
    "PII Block", 
    "/v1/chat/completions",
    {"X-Theta-Override": "2.0"}, 
    {"messages": [{"role": "user", "content": "My SSN is 999-12-3456"}]}
)

# Test 4: Unregistered agent key block
run_test(
    "Unregistered Agent Key Block", 
    "/v1/agent/action",
    {"X-Agent-Key": "rogue-agent-fake-key-xyz"}, 
    {"tool": "read_file", "args": {"path": "/etc/passwd"}}
)
