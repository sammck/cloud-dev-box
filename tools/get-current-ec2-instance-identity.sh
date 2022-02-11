#!/bin/bash

set -e

RAW_DATA="$(curl -s -m 3 http://169.254.169.254/latest/dynamic/instance-identity/document 2>/dev/null || true)"


if [ -z "$RAW_DATA" ]; then
  echo "ERROR: Not running in an ec2 instance" >&2
  exit 1
fi

jq . <<< "$RAW_DATA"

