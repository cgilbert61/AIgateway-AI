import psycopg2

try:
    conn = psycopg2.connect("postgres://postgres:postgres@localhost:5432/gateway_db?sslmode=disable")
    cursor = conn.cursor()
    cursor.execute("SELECT key_id, agent_name, is_active FROM authorized_agent_keys")
    rows = cursor.fetchall()
    print("Agent keys in DB:")
    for row in rows:
        print(f"Key: {row[0]}, Name: {row[1]}, Active: {row[2]}")
except Exception as e:
    print(f"Failed to query database: {e}")
