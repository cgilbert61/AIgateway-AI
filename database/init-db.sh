#!/bin/bash
set -e

# Run schema setup inside the postgres database
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    \i /tmp/schema.sql
EOSQL
