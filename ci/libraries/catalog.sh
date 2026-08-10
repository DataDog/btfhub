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
    # shellcheck disable=SC2034
    for i in $(seq 1 5); do
        # shellcheck disable=SC2015
        git clone --quiet --depth=1 "https://github.com/DataDog/rc-employee-configurations" && break || true
        log "Attempt #$i to clone https://github.com/DataDog/rc-employee-configurations failed." ERROR
    done
    if [ ! -d "rc-employee-configurations" ]; then
        log "Cloning https://github.com/DataDog/rc-employee-configurations failed after max retries."
        return 1
    fi
    log "Cloning https://github.com/DataDog/rc-employee-configurations... Done"

    curdir="$(pwd)"
    mkdir bin
    # Build outside the repo working tree so the binary doesn't show up in
    # `git status --porcelain` and pollute the dirty-tree checks below.
    RC_BIN="$curdir/bin/rc-employee-configurations"
    export RC_BIN

    pushd rc-employee-configurations
    log "Building rc-employee-configurations..."
    for i in $(seq 1 5); do
        # shellcheck disable=SC2015
        go build -v -o "$RC_BIN" . && break || true
        log "Attempt #$i to build rc-employee-configurations failed." ERROR
    done
    log "Building rc-employee-configurations... Done"
    popd
}

# Reset signed/BTF_DD/ to its state on main, undoing any prior signing done on
# this branch. Scoped to BTF_DD only — other products' signed/ dirs are managed
# by their own workflows and must not be touched here.
# Forward-only commit: no history rewrite, no force push needed.
reset_signed_to_base() {
    local destination=$1

    # Signing only happens for staging and prod (mirrors the check in sign_catalog).
    case "$destination" in
        staging|prod) ;;
        *) return 0 ;;
    esac

    git fetch --quiet --depth=1 origin main
    git rm -rf --quiet --ignore-unmatch signed/BTF_DD/
    git checkout origin/main -- signed/BTF_DD/ 2>/dev/null || true

    if git diff --cached --quiet; then
        return 0
    fi

    git commit --quiet -m "Reset signed/BTF_DD for ${destination}"
    log "Reset signed/BTF_DD to base state."
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

    TMPDIR="$(mktemp -d)"
    export TMPDIR

    pushd "$TMPDIR"
    setup_catalog_repo

    pushd rc-employee-configurations
    log "Checking out branch from git..."
    local GIT_BRANCH
    GIT_BRANCH=$(get_branch_name "$destination")
    if git fetch origin "$GIT_BRANCH"; then
        log "Fetching branch from origin/$GIT_BRANCH"
        git remote set-branches --add origin "$GIT_BRANCH"
        git fetch origin "$GIT_BRANCH"
        git checkout -b "$GIT_BRANCH" origin/"$GIT_BRANCH"
        reset_signed_to_base "$destination"
    else
        log "Checking out $GIT_BRANCH locally"
        git checkout -b "$GIT_BRANCH"
    fi
    log "Checking out branch from git... Done"

    # generate catalog updates
    "$CI_PROJECT_DIR/btfhub" -hash-dir "$CI_PROJECT_DIR/.tmp/hash" -catalog-json "configs/BTF_DD/btfs.${destination}.json" catalog-update

    if [[ $(git status --porcelain) ]]; then
        log "Catalog update succeeded, committing changes."
        cat <<EOF | git commit --quiet -a -F -
BTF_DD $destination catalog update

Updated by $CI_JOB_URL
EOF

        # Pull any concurrent updates before signing so signed/ covers the
        # final configs/ tree we're about to push.
        if git fetch origin "$GIT_BRANCH"; then
            log "Pulling origin $GIT_BRANCH... "
            git pull origin "$GIT_BRANCH" --allow-unrelated-histories
            log "Pulling origin $GIT_BRANCH... Done"
        fi

        # TODO enable signing once CI identity setup
        # sign_catalog "$destination"

        if [[ "${CI_COMMIT_BRANCH}" == "main" && "${CI_PIPELINE_SOURCE}" == "schedule" ]]; then
            log "Pushing changes to origin $GIT_BRANCH... "
            git push --quiet -u origin "$GIT_BRANCH"
            log "Pushing changes to origin $GIT_BRANCH... Done"

            local pr_name
            local pr_number
            pr_name="[$destination] BTF Catalog updates"
            pr_number=$(gh pr list --state open --head "$GIT_BRANCH" 2>/dev/null | awk '{print $1}')
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
    rm -rf "$TMPDIR"
}
