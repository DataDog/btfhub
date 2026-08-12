#!/bin/bash

get_branch_name() {
    set -e
    set +x

    local destination=$1

    echo "btf/automated/${destination:-staging}"
}

setup_catalog_repo() {
    set -e
    set +x

    log "Cloning https://github.com/DataDog/rc-employee-configurations..."
    mkdir rc-employee-configurations
    pushd rc-employee-configurations
    git init
    git remote add origin https://github.com/DataDog/rc-employee-configurations
    git fetch --filter=blob:none --no-tags --progress --depth=1 origin main
    git sparse-checkout set --cone configs/BTF_DD signed/BTF_DD
    git checkout --progress --force main
    popd
    log "Cloning https://github.com/DataDog/rc-employee-configurations... Done"

    curdir="$(pwd)"
    mkdir bin
    # Build outside the repo working tree so the binary doesn't show up in
    # `git status --porcelain` and pollute the dirty-tree checks below.
    RC_BIN="$curdir/bin/rc-employee-configurations"
    export RC_BIN

    pushd rc-employee-configurations
    log "Building rc-employee-configurations..."
    go build -v -o "$RC_BIN" .
    log "Building rc-employee-configurations... Done"
    popd
}

# Sign the catalog for staging or prod using the CI Vault key.
# Commits the signed output as "Sign config for <destination>".
# No-op for trial.
#
# Requires the CI job to have a CI Identities GitLab ID token
# (id_tokens: CI_IDENTITIES_GITLAB_ID_TOKEN with aud: ci-identities).
sign_catalog() {
    local destination=$1

    local vault_key
    case "$destination" in
        staging)
            vault_key="TODO"
            ;;
        prod)
            vault_key="TODO"
            ;;
        *)
            return 0
            ;;
    esac

    log "Signing catalog for ${destination}..."
    VAULT_ADDR="https://vault.us1.ddbuild.io" \
    ci-identities-ci-job-client --mode=k8s --dns-type=developer-gateway vault env -- \
        "$RC_BIN" sign \
            --product BTF_DD \
            --env "$destination" \
            --vault-engine crypto/ci \
            --vault-key "$vault_key" \
            --vault-identity "TODO"
    log "Signing catalog for ${destination}... Done"

    # The sign command writes both the new signed targets file
    # (signed/<PRODUCT>/<env>/N.<PRODUCT>.json) and a new versioned snapshot
    # of the catalog (configs/<PRODUCT>/generated_versions/N.*.json), so we
    # need to stage both directories.
    git add -A signed/ configs/
    if git diff --cached --quiet; then
        log "Sign command produced no changes, this is unexpected" ERROR
        return 1
    fi

    git commit --quiet -m "Sign config for ${destination}"
}

open_or_update_catalog_pr() {
    set -e
    set +x

    local destination=$1

    RCDIR="$(mktemp -d)"
    export RCDIR

    pushd "$RCDIR"
    setup_catalog_repo

    pushd rc-employee-configurations
    log "Checking out branch from git..."
    local GIT_BRANCH
    GIT_BRANCH=$(get_branch_name "$destination")
    if git ls-remote --exit-code origin "$GIT_BRANCH"; then
        log "Fetching branch from origin/$GIT_BRANCH"
        git fetch origin "$GIT_BRANCH:$GIT_BRANCH"
        git checkout "$GIT_BRANCH"
        CREATE_FLAG=""
        git reset --hard origin/main
    else
        log "Checking out $GIT_BRANCH locally"
        git checkout -b "$GIT_BRANCH" origin/main
        CREATE_FLAG="--create-branch"
    fi
    REV=$(git rev-parse HEAD)
    log "Checking out branch from git... Done"

    # generate catalog updates
    "$CI_PROJECT_DIR/btfhub" -hash-dir "$CI_PROJECT_DIR/.tmp/hash" -catalog-json "configs/BTF_DD/btfs.${destination}.json" catalog-update

    if [[ $(git status --porcelain) ]]; then
        log "Catalog update succeeded, committing changes."
        cat <<EOF | git commit --quiet -a -F -
BTF_DD $destination catalog update

Updated by $CI_JOB_URL
EOF

        # TODO enable signing once CI identity setup
        # sign_catalog "$destination"

        if [[ "${CI_COMMIT_BRANCH}" == "main" && "${CI_PIPELINE_SOURCE}" == "schedule" ]]; then
            log "Pushing changes to origin $GIT_BRANCH... "
            commit-headless push -T DataDog/rc-employee-configurations --branch "${GIT_BRANCH}" ${CREATE_FLAG:+"$CREATE_FLAG"} --force --head-sha "${REV}" --reset
            log "Pushing changes to origin $GIT_BRANCH... Done"

            local pr_name
            local pr_number
            pr_name="[$destination] BTF Catalog updates"
            pr_number=$(gh pr list -R DataDog/rc-employee-configurations --state open --head "$GIT_BRANCH" 2>/dev/null | awk '{print $1}')
            if [ -z "${pr_number}" ]; then # PR does not exist
                log "Creating PR $pr_name."
                cat <<EOF |
Add new entries to the $destination catalog.

This PR was automatically generated from $CI_PIPELINE_URL
EOF
                gh pr create --head "$GIT_BRANCH" --body-file - --title "$pr_name"
            else # PR exists
                log "PR #$pr_number already exists, updating it."
            fi
        fi
    else
        log "No changes to commit, skipping PR creation."
    fi

    popd
    popd
    rm -rf "$RCDIR"
}
