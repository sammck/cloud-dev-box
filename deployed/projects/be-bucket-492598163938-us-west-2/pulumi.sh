#!/bin/bash

set -eo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( dirname "$( dirname "$( dirname  "$SCRIPT_DIR" )" )" )"
PULUMI_INSTALL_DIR="$PROJECT_DIR/install/pulumi"
PULUMI="$PULUMI_INSTALL_DIR/bin/pulumi"

export PULUMI_BACKEND_URL="file://$SCRIPT_DIR/state"
export PULUMI_HOME="$PULUMI_INSTALL_DIR"
export PULUMI_CONFIG_PASSPHRASE="$(secret-kv -r get "pulumi/passphrase")" || exit $?
"$PULUMI" -C "$SCRIPT_DIR" "$@"
