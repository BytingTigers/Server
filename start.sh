#!/bin/bash

redis-server --daemonize yes

service mysql start

sleep 5

{ /chat/start 5000 & /auth/start 5001; }
