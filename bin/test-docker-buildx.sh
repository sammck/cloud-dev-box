#!/bin/bash

# See https://medium.com/@artur.klauser/building-multi-architecture-docker-images-with-buildx-27d80f7e2408

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "$SCRIPT_DIR/bash-helpers.sh"

# This wrapper will handle the case where we've been added to the docker group but have not yet
# logged out/in
function gdocker() {
    run_with_group docker docker "$@" || return $?
    # return 0
}

tmp_dir="$(get_tmp_dir)" || exit $?

cd $tmp_dir
rm -fr docker-buildx-test
mkdir docker-buildx-test
cd docker-buildx-test

cat > Dockerfile <<HERE
FROM alpine:latest
RUN apk add --update binutils
CMD readelf -h /bin/sh
HERE

gdocker buildx rm buildx-test >/dev/null 2>&1 || true

function do_test() {
    gdocker build -t buildx-test . || return $?
    gdocker buildx create --name buildx-test > /dev/null || return $?
    gdocker buildx use buildx-test || return $?
    gdocker buildx inspect --bootstrap || return $?
    gdocker buildx prune -a -f || return $?
    gdocker buildx build  --progress plain . || return $?
    gdocker buildx build -t buildx-test-arm64 --platform linux/arm64 --load . || return $?
    gdocker buildx build -t buildx-test-amd64 --platform linux/amd64 --load . || return $?
    echo
    echo "Execution in conventionally built container:"
    echo
    gdocker run --rm buildx-test || return $?
    echo
    echo "Execution in x86_64 container:"
    echo
    gdocker run --rm --platform linux/amd64 buildx-test-amd64 || return $?
    echo
    echo "Execution in aarch64 container:"
    echo
    gdocker run --rm --platform linux/arm64 buildx-test-arm64 || return $?
    gdocker image rm buildx-test-amd64 || return $?
    gdocker image rm buildx-test-arm64 || return $?
    gdocker image rm buildx-test || return $?
}
EXIT_CODE=0
do_test || EXIT_CODE=$?
gdocker buildx use default >/dev/null 2>&1 || true
gdocker buildx rm buildx-test >/dev/null 2>&1 || true

echo >&2
if [[ $EXIT_CODE -ne 0 ]]; then
    echo "Test failed with exit code $EXIT_CODE" >&2
    exit 1
else
    echo "End of test, success!" >&2
fi

should_wrap=0
should_run_with_group "docker" || should_wrap=$?
if [[ "$should_wrap" -eq 0 ]]; then
    echo "WARNING: Command 'docker' requires membership in OS group 'docker', which is newly added for" >&2
    echo "user $(get_current_os_user), and is not yet effective for the current process. Please logout" >&2
    echo " and log in again, or in the mean time run docker with:" >&2
    echo "         sudo -E -u $user docker [<arg>...]" >&2
fi