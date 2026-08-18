#!/bin/bash

##
# Logs a message with a date
# Examples:
#   "hello, world" WARN => ø
log() { set -e
  local message=$1     # what to log, as a single string
  local error_level=$2 # the log level that will prefix the message, defaults to INFO if empty

  if [[ -z "$error_level" ]]; then
    error_level=INFO
  fi

  echo "${error_level} [$(date "+%Y.%m.%d-%H:%M:%S %Z")] ${message}" 1>&2
}

add_exit_trap() {
    local cmd=$1 # command(s) to add
    local old combined

    # Compute effective trap list for current (sub)shell
    # Based on info from https://stackoverflow.com/a/59307894/5116073
    trap -- KILL >/dev/null 2>&1 || true
    old=$( (trap -p EXIT) )

    # extract/cleanup the existing registered command(s)
    old=${old#*\'}         # remove leading "trap -- '"
    old=${old%\'*}         # remove trailing "' EXIT"
    old=${old//"'\''"/"'"} # unescape every '\'' to '

    # if command is already registered exactly, do nothing
    if [[ ";$old;" == *";$cmd;"* ]]; then
        return 0
    fi

    # build the new combined handler
    if [[ -n $old ]]; then
        combined="$old;$cmd"
    else
        combined="$cmd"
    fi

    # register the new combined handler
    trap -- "$combined" EXIT
}

setup_gh_token() {
    set -e
    set +x

    local policy
    policy="read"
    if [[ "${CI_COMMIT_BRANCH}" == "main" ]]; then
        # https://github.com/DataDog/.github/blob/main/.github/chainguard/btfhub.create-pull-request.sts.yaml
        policy="create-pull-request"
    fi

    log "Obtaining GitHub token via Octo-STS..."
    GITHUB_TOKEN=$(dd-octo-sts token --scope "DataDog" --policy "btfhub.${policy}")
    export GITHUB_TOKEN
    # shellcheck disable=SC2064
    add_exit_trap "set +x; dd-octo-sts revoke -t $GITHUB_TOKEN 2>/dev/null || true"
    if [[ -n "$GITHUB_TOKEN" ]]; then
        log "Successfully obtained GitHub token via Octo-STS"
    else
        log "Octo-STS token exchange failed" ERROR
        exit 1
    fi

    # shellcheck disable=SC2016
    git config --global credential.helper \
        '!f() { echo username=x-access-token; echo "password=$GITHUB_TOKEN"; };f'
    git config --global user.email "ci@datadoghq.com"
    git config --global user.name "CI Bot"
    git config --global init.defaultBranch main
}
