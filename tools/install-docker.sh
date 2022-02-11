#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "$SCRIPT_DIR/bash-helpers.sh"

min_docker_client_version="20.0.0"
min_docker_server_version="$min_docker_client_version"

force=""
if [ "$1" == "--force" ]; then
  force=1
fi


install_client=1

if [ "$force" != "1" ]; then
    if command_exists docker; then
        docker_cmd="$(command -v docker)"
        docker_client_version="$(docker version -f'{{.Client.Version}}' 2>/dev/null || true)"
        if [ -z "$docker_client_version" ]; then
            echo "Docker client is installed and in PATH at $docker_cmd, but the client version cannot be fetched." >&2
            echo "Please uninstall and run install-docker.sh again, or run with --force." >&2
            exit 1
        fi
        if check_version_ge "$docker_client_version" "$min_docker_client_version"; then
            echo "Docker client version $docker_client_version is installed and in PATH at $docker_cmd, and" >&2
            echo "meets the minimum version $min_docker_client_version. No update is necessary. If you" >&2
            echo "wish to update, please run install-docker.sh again with --force." >&2
            install_client=""
        else
            echo "Docker client version $docker_client_version is installed and in PATH at $docker_cmd, but" >&2
            echo "does not meet the minimum version $min_docker_client_version. Attempting to update." >&2
        fi
    fi
else
    echo "Forcing install/upgrade of docker" >&2
fi

if [ "$install_client" == "1" ]; then
    uninstall_os_packages docker-engine docker.io containerd runc

    pkglist=()

    add_os_packages_if_missing        pkglist ca-certificates curl gnupg lsb-release
    add_os_package_if_command_missing pkglist sha256sum coreutils

    update_and_install_os_packages "${pkglist[@]}"

    install_gpg_keyring_if_missing "https://download.docker.com/linux/ubuntu/gpg" "/usr/share/keyrings/docker-archive-keyring.gpg"
    update_apt_sources_list "/etc/apt/sources.list.d/docker.list" "/usr/share/keyrings/docker-archive-keyring.gpg" "https://download.docker.com/linux/ubuntu"

    update_and_install_os_packages_if_missing containerd.io

    pkglist=()
    if [ "$force" == "1" ]; then
        add_os_packages pkglist docker-ce docker-ce-cli
    else
        add_os_package_if_outdated pkglist docker-ce "$min_docker_client_version"
        add_os_package_if_outdated pkglist docker-ce-cli "$min_docker_client_version"
    fi
    update_and_upgrade_os_packages "${pkglist[@]}"

    if ! command_exists docker; then
        echo "ERROR: Docker client still not found in PATH after install/upgrade." >&2
        exit 1
    fi

    docker_cmd="$(command -v docker)"
    docker_client_version="$(docker version -f'{{.Client.Version}}' 2>/dev/null || true)"
    if [ -z "$docker_client_version" ]; then
        echo "ERROR: Docker client installed/upgraded and in PATH at $docker_cmd, but the client version cannot be fetched." >&2
        echo "Please uninstall and run install-docker.sh again" >&2
        exit 1
    fi
    if ! check_version_ge "$docker_client_version" "$min_docker_client_version"; then
        echo "ERROR: Docker client installed/upgraded, but version $docker_client_version still" >&2
        echo "does not meet the minimum version $min_docker_client_version." >&2
        exit 1
    fi
    echo "Docker client version successfully installed/upgraded to version $docker_client_version" >&2
fi

docker_server_version="$(docker version -f'{{.Server.Version}}' 2>/dev/null || true)"

if [ -z "$docker_server_version" ]; then
    docker_gid="$(get_gid_of_group docker 2>/dev/null || true)"
    if [ -z "$docker_gid" ]; then
        echo "Docker server is not reachable by the client, and there is no 'docker' linux group present." >&2
        echo "Please update docker client configuration to allow access to the docker server." >&2
        exit 1
    fi

    if ! os_group_includes_user docker; then
        echo "User $USER is not in os group 'docker'; adding..." >&2
        if ! os_group_add_user docker; then
            echo "Docker server is not reachable by the client, and adding user $USER to os group 'docker' failed." >&2
            echo "Please update docker client configuration to allow access to the docker server." >&2
            exit 1
        fi
    fi

    docker_server_version="$(run_with_group docker docker version -f'{{.Server.Version}}' 2>/dev/null || true)"
    if [ -z "$docker_server_version" ]; then
        echo "Docker server is not reachable by the client, even after adding user $USER to os group 'docker'." >&2
        echo "Please update docker client configuration to allow access to the docker server." >&2
        exit 1
    fi
fi

if ! check_version_ge "$docker_server_version" "$min_docker_server_version"; then
    echo "Docker server is reachable by the client, but its version $docker_server_version" >&2
    echo "does not meet the minimum version $min_docker_server_version. Please update" >&2
    echo "the docker server (which may be remote)." >&2
    exit 1
fi

echo "Docker server is reachable by the docker client, and its version, $docker_server_version," >&2
echo "meets the minimum version $min_docker_server_version. No further update of the docker server is necessary." >&2

# stuff for multi-arch builds
pkglist=()

add_os_packages_if_missing        pkglist binfmt-support qemu-user-static

update_and_install_os_packages "${pkglist[@]}"

function get_binfmt_field() {
    local target_architecture="$1"; shift
    local field_name="$1"; shift
    local var_binfmts_pathname="$/var/lib/binfmts/qemu-$target_architecture"
    local value;
    if value="$(sed -n 's/^'"$field_name"' \(.\+\)$/\1/p' $var_binfmts_pathname)"; then
        echo "$value"
    else
        echo "Unable to read binfmts field '$field_name' from $var_binfmts_pathname; exit code $?" >&2
        return 1
    fi
    return 0
}

function hex_to_escaped_hex() {
    local hex="$1"; shift
    local result="$(sed 's/\(..\)/\\x\1/g' <<< "$hex")" || return $?
    echo "$result"
    # return 0
}

function fix_binfmt_qemu_binary() {
    local target_architecture="$1"; shift

    local var_binfmts_pathname="/var/lib/binfmts/qemu-$target_architecture"
    local package_name
    if package_name="$(sed '1q;d' "$var_binfmts_pathname")"; then
        if [ "$package_name" == "" ]; then
            echo "Unexpected value '$is_fixed_binary' in line 10 of $var_binfmts_pathname" >&2
            return 1
        fi
        local magic="$(get_binfmt_field "$target_architecture" magic)" || return $?
        local escaped_magic="$(hex_to_escaped_hex "$magic")" || return $?
        local mask="$(get_binfmt_field "$target_architecture" mask)" || return $?
        local escaped_mask="$(hex_to_escaped_hex "$mask")" || return $?
        local interpreter="$(get_binfmt_field "$target_architecture" interpreter)" || return $?
        local offset="$(get_binfmt_field "$target_architecture" offset)" || return $?
        echo "Reregistering QEMU binfmts binary /usr/bin/qemu-$target_architecture-static to set --fix-binary option (requires sudo)" >&2
        sudo update-binfmts --package "$package_name" \
            --remove "qemu-$target_architecture" "/usr/bin/qemu-$target_architecture-static" || return $?
        sudo update-binfmts --package "$package_name" \
            --install "qemu-$target_architecture" "$interpreter" \
            --offset "$offset" --magic "$escaped_magic" --mask "$escaped_mask" \
            --credentials yes --fix-binary yes || return $?
    else
        echo "Unable to read binfmts package name from line 1 of $var_binfmts_pathname" >&2
        return 1
    fi
    return 0
}

function fix_binfmt_qemu_binary_if_needed() {
    local target_architecture="$1"; shift

    local var_binfmts_pathname="/var/lib/binfmts/qemu-$target_architecture"
    local is_fixed_binary
    if is_fixed_binary="$(sed '10q;d' "$var_binfmts_pathname")"; then
        if [ "$is_fixed_binary" == "yes" ]; then
            return 0
        else
            if [ "$is_fixed_binary" != "" ]; then
                echo "Unexpected value '$is_fixed_binary' in line 10 of $var_binfmts_pathname" >&2
                return 1
            fi
            fix_binfmt_qemu_binary "$target_architecture" || return $?
        fi
    else
        echo "Unable to read binfmts fix-binary flag from line 10 of $var_binfmts_pathname" >&2
        return 1
    fi

    return 0
}

function fix_all_binfmt_qemu_binaries_if_needed() {
    local binfmt_misc_filename
    for binfmt_misc_filename in /proc/sys/fs/binfmt_misc/qemu-*; do
        local target_architecture="${binfmt_misc_filename/*qemu-/}"
        fix_binfmt_qemu_binary_if_needed "$target_architecture" || return $?
    done
    return 0
}

fix_all_binfmt_qemu_binaries_if_needed
echo "All QEMU interpreter binaries have been registered with binfmts as --fix-binary; no further update necessary" >&2
