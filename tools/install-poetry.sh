#!/bin/bash

set -e

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "$SCRIPT_DIR/bash-helpers.sh"

MIN_POETRY_VERSION=1.1.12

echo "Installing/updating poetry" >&2

curl -sSL https://install.python-poetry.org | python3 -
if ! command_exists poetry; then
    echo "The poetry command is still not in PATH after installation; check to make sure" >&2
    echo "$HOME/.local/bin is in your PATH. Add to $HOME/~profile if desired." >&2
    exit 1
fi

POETRY_VERSION="$(poetry --version | cut -d' ' -f3 | tr -cd '0-9.')"
if ! check_version_ge "$POETRY_VERSION" "$MIN_POETRY_VERSION"; then
  echo "The poetry command version $POETRY_VERSION is still below the minimum version $MIN_POETRY_VERSION after update" >&2
fi

POETRY_CMD="$(command -v poetry)"
echo "Poetry version $POETRY_VERSION successfully installed and in PATH at $POETRY_CMD" >&2
