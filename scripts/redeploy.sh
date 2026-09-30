#!/usr/bin/env bash
# =====================================================================
# PhishLens: one-command redeploy on the VM.
# =====================================================================
#   ~/PhishLens/scripts/redeploy.sh             update to origin/main, rebuild, restart
#   ~/PhishLens/scripts/redeploy.sh --no-pull   rebuild the current checkout
#   ~/PhishLens/scripts/redeploy.sh --rollback  restart the previous image
#
# Steps: pull origin/main, build a new image, keep the running one as
# phishlens:previous, restart the container, wait for /health (the model
# loads before the server answers), run a smoke /analyse, then copy the
# landing page. If the new container does not come up healthy, the
# previous image is started again automatically.
# =====================================================================
set -euo pipefail

REPO="${PHISHLENS_REPO:-$HOME/PhishLens}"
SITE_DIR="${PHISHLENS_SITE_DIR:-$HOME/phishlens-site}"
NAME="phishlens"
IMAGE="phishlens"
PORT_IN_CONTAINER=7860
HEALTH_TIMEOUT=300          # seconds; the first boot downloads the model

run_container() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --restart=always \
        --network web \
        --env-file "$HOME/.phishlens.env" \
        -v "$HOME/phishlens_data:/data" \
        -v "$HOME/phishlens_model:/home/user/app/model" \
        -v "$HOME/phishlens_agents:/home/user/app/agents" \
        --name "$NAME" "$1" >/dev/null
}

# Calls the API from inside the container (no port is published on the
# host: Caddy talks to it over the "web" network).
in_container() {
    docker exec "$NAME" python -c "$1"
}

wait_healthy() {
    local waited=0
    printf "   waiting for /health"
    while [ "$waited" -lt "$HEALTH_TIMEOUT" ]; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
            echo; echo "   container stopped"; return 1
        fi
        if in_container "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$PORT_IN_CONTAINER/health', timeout=3)" >/dev/null 2>&1; then
            echo " ok (${waited}s)"; return 0
        fi
        printf "."; sleep 5; waited=$((waited + 5))
    done
    echo; echo "   no answer after ${HEALTH_TIMEOUT}s"; return 1
}

smoke_test() {
    in_container "
import json, urllib.request
req = urllib.request.Request('http://127.0.0.1:$PORT_IN_CONTAINER/analyse',
    data=json.dumps({'raw_text': 'Hi team, the meeting moved to 3pm tomorrow. See you there.'}).encode(),
    headers={'Content-Type': 'application/json'})
r = json.load(urllib.request.urlopen(req, timeout=60))
assert r['verdict'] in ('safe', 'phishing'), r
print('   smoke /analyse ok: verdict=%s score=%.3f path=%s' % (r['verdict'], r['fused_score'], r['trust_path']))
"
}

rollback() {
    if ! docker image inspect "$IMAGE:previous" >/dev/null 2>&1; then
        echo "!! no previous image to roll back to"; exit 1
    fi
    echo "== Rolling back to $IMAGE:previous"
    run_container "$IMAGE:previous"
    if wait_healthy; then
        docker image tag "$IMAGE:previous" "$IMAGE:latest"
        echo "== Rolled back, previous version is serving again."
    else
        echo "!! the previous image does not start either:"; docker logs --tail 40 "$NAME"; exit 1
    fi
}

# Everything runs from main(), so bash has read the whole file before
# "git reset" can replace this script with a newer version mid-run.
main() {
    case "${1:-}" in
        --rollback) rollback; exit 0 ;;
        --no-pull|"") ;;
        *) echo "usage: $0 [--no-pull | --rollback]"; exit 2 ;;
    esac

    cd "$REPO"

    if [ "${1:-}" != "--no-pull" ]; then
        echo "== 1. Update code"
        OLD=$(git rev-parse --short HEAD)
        git fetch --quiet origin --prune --tags
        git reset --quiet --hard origin/main
        NEW=$(git rev-parse --short HEAD)
        if [ "$OLD" = "$NEW" ]; then
            echo "   already at $NEW"
        else
            echo "   $OLD -> $NEW"; git log --oneline "$OLD..$NEW" | sed 's/^/   /' || true
        fi
    fi
    VERSION=$(git describe --tags --always 2>/dev/null || git rev-parse --short HEAD)

    echo "== 2. Build image ($VERSION)"
    docker build --quiet -f backend/Dockerfile.cloud -t "$IMAGE:new" backend >/dev/null
    echo "   built"

    echo "== 3. Restart"
    if docker image inspect "$IMAGE:latest" >/dev/null 2>&1; then
        docker image tag "$IMAGE:latest" "$IMAGE:previous"
    fi
    docker image tag "$IMAGE:new" "$IMAGE:latest"
    run_container "$IMAGE:latest"

    echo "== 4. Health check"
    if ! wait_healthy || ! smoke_test; then
        echo "!! new version is not healthy, last logs:"
        docker logs --tail 40 "$NAME" || true
        rollback
        exit 1
    fi

    echo "== 5. Landing page"
    if [ -d "$SITE_DIR" ]; then
        rsync -a --delete "$REPO/site/" "$SITE_DIR/"
        echo "   copied to $SITE_DIR"
    else
        echo "   $SITE_DIR not found, skipped"
    fi

    echo "== 6. Clean up old images"
    docker image rm "$IMAGE:new" >/dev/null 2>&1 || true
    docker image prune -f >/dev/null
    echo
    echo "== Deployed $VERSION. Logs: docker logs -f $NAME   Undo: $0 --rollback"
}

main "$@"
