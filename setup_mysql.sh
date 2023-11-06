#!/bin/bash

echo "MySQL initialization start..."

# Create the database and the 'users' table within MySQL
mysql -u root <<-EOSQL
    CREATE DATABASE IF NOT EXISTS auth;
    USE auth;

    CREATE TABLE IF NOT EXISTS users (
        id int NOT NULL AUTO_INCREMENT,
        username varchar(255) NOT NULL,
        password_hash char(64) NOT NULL,
        salt char(32) NOT NULL,
        PRIMARY KEY (id)
    );
EOSQL

echo "MySQL initialization finished..."
