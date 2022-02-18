#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

REGION="$("$SCRIPT_DIR/get-current-ec2-instance-identity.sh" | jq -r .region)"

if [ -z "$REGION" ]; then
  exit 1
fi

echo "$REGION"
