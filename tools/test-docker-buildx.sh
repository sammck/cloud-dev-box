#!/bin/bash

# See https://medium.com/@artur.klauser/building-multi-architecture-docker-images-with-buildx-27d80f7e2408

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "$SCRIPT_DIR/bash-helpers.sh"

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

docker buildx rm buildx-test >/dev/null 2>&1 || true

function run_with_builder() {
    docker build -t buildx-test . || return $?
    docker buildx create --name buildx-test > /dev/null || return $?
    docker buildx use buildx-test || return $?
    docker buildx inspect --bootstrap || return $?
    docker buildx prune -a -f || return $?
    docker buildx build  --progress plain . || return $?
    docker buildx build -t buildx-test-arm64 --platform linux/arm64 --load . || return $?
    docker buildx build -t buildx-test-amd64 --platform linux/amd64 --load . || return $?
    echo
    echo "Execution in conventionally built container:"
    echo
    docker run --rm buildx-test || return $?
    echo
    echo "Execution in x86_64 container:"
    echo
    docker run --rm --platform linux/amd64 buildx-test-amd64 || return $?
    echo
    echo "Execution in aarch64 container:"
    echo
    docker run --rm --platform linux/arm64 buildx-test-arm64 || return $?
    docker image rm buildx-test-amd64 || return $?
    docker image rm buildx-test-arm64 || return $?
    docker image rm buildx-test || return $?
}
EXIT_CODE=0
run_with_builder || EXIT_CODE=$?
docker buildx use default >/dev/null 2>&1 || true
docker buildx rm buildx-test >/dev/null 2>&1 || true

echo >&2
if [[ $EXIT_CODE -ne 0 ]]; then
    echo "Test failed with exit code $EXIT_CODE" >&2
else
    echo "End of test, success!" >&2
fi

exit $EXIT_CODE
