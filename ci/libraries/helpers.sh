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

setup_gh_token() {
    set -e
    set +x

    log "Obtaining GitHub token via Octo-STS..."
    # https://github.com/DataDog/.github/blob/main/.github/chainguard/btfhub.create-pull-request.sts.yaml
    GITHUB_TOKEN=$(dd-octo-sts token --scope "DataDog" --policy "btfhub.create-pull-request")
    export GITHUB_TOKEN
    if [[ -n "$GITHUB_TOKEN" ]]; then
        log "Successfully obtained GitHub token via Octo-STS"
    else
        log "Octo-STS token exchange failed" ERROR
        exit 1
    fi

    # shellcheck disable=SC2016
    git config --global credential.helper \
        '!f() { echo username=x-access-token; echo "password=$GITHUB_TOKEN"; };f'
}
