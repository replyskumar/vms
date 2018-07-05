#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "postgres" <<-EOSQL
	CREATE USER vms WITH PASSWORD 'vms';
	CREATE DATABASE vms;
	GRANT ALL PRIVILEGES ON DATABASE vms TO vms;
EOSQL
