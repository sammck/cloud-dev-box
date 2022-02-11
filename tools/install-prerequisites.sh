#!/bin/bash

#set -x
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "$SCRIPT_DIR/bash-helpers.sh"

pkglist=()

add_os_package_if_command_missing pkglist sha256sum coreutils
add_os_package_if_command_missing pkglist curl
add_os_package_if_command_missing pkglist python3

update_and_install_os_packages "${pkglist[@]}"

"$SCRIPT_DIR/install-poetry.sh"
"$SCRIPT_DIR/install-aws-cli.sh"
"$SCRIPT_DIR/install-pulumi.py"
