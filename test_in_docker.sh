#!/bin/bash

# Run CMDLINE in cni-plugins-test:TAG_NAME container with cwd volume mounted
# usage: test_in_docker.sh <TAG_NAME> <CMDLINE>
# e.g.
# test_in_docker.sh latest PKG="github.com/containernetworking/plugins/plugins/meta/firewall" ./test_linux.sh
# test_in_docker.sh latest 'PKG=$(go list ./... | grep -v vrf | xargs echo) ./test_linux.sh'
# test_in_docker.sh latest $'bash -c \'[[ "$(gofmt -d ./plugins/)" = "" ]] && echo fmtok || echo fmtng\''

TAG=${1}
shift

DOCKER=${DOCKER:-docker}

exec_cnipluginstest_container() {
  ${DOCKER} run --rm --privileged \
    -e GOFLAGS='-buildvcs=false' \
    -v $(eval echo "~${SUDO_USER-${USER}}")/go:/go \
    -v $(realpath "${PWD}"):${PWD} \
    -w $(realpath "${PWD}") \
    cni-plugins-test:${TAG} \
    sh -c "go env -w GOPATH=/go ; export PATH=\$PATH:/go/bin ; $@ ; echo \$? > /tmp/EXITCODE ; chown -R ${SUDO_UID-$(id -u)} ./ ; chgrp -R ${SUDO_GID-$(id -g)} ./ ; echo ; cat /tmp/EXITCODE" \
  | tr -d '\r'
}

separate_stdouterr() {
  ARGS="$@"

  tmpfile="$(mktemp)"
  STDOUT=$(exec_cnipluginstest_container "${ARGS}" 2>${tmpfile})
  STDERR=$(cat ${tmpfile})
  rm -f ${tmpfile}

  # ignore exitcode
  [[ "${STDOUT}" =~ ^[0-9]*$ ]] || ( [[ "$(echo "${STDOUT}" | tail -n 2 | head -n +1 )" = "" ]] && echo "${STDOUT}" | head -n -2 || echo "${STDOUT}" | head -n -1 )
  # stderr if exists
  [[ "${STDERR}" != "" ]] && echo "${STDERR}" >&2

  # exitcode is the lastline of stdout
  exit $(echo "${STDOUT}" | tail -n 1)
}

separate_stdouterr "$@"
