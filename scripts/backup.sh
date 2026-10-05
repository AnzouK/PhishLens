#!/usr/bin/env bash
# =====================================================================
# PhishLens: weekly server backup to an rclone remote (run on the server).
# =====================================================================
#   ~/PhishLens/scripts/backup.sh            back up now
#   ~/PhishLens/scripts/backup.sh --list     list the backups on Drive
#
# What is saved (everything else comes back from GitHub or Hugging Face):
#   - the server configuration: ~/.phishlens.env and ~/Caddyfile
#   - the backend data folder: ~/phishlens_data (SQLite files are copied
#     with SQLite's own backup API, so a write in progress cannot corrupt
#     the copy)
#   - the web-server access logs (30 days, used by phishlens-stats.sh)
#
# The archive goes to the rclone remote $PHISHLENS_BACKUP_REMOTE (default
# "phishlens-backup:"). Use an rclone "crypt" remote over your storage
# (Google Drive, S3, ...): the archive holds the env file, so it should be
# encrypted on the server before upload. Archives older than
# $PHISHLENS_BACKUP_KEEP_DAYS (default 60, about 8 weekly backups) are
# deleted from the remote.
#
# Weekly with cron (Sunday 03:00):
#   0 3 * * 0 bash ~/PhishLens/scripts/backup.sh >> ~/phishlens-backup.log 2>&1
# =====================================================================
set -euo pipefail

REMOTE="${PHISHLENS_BACKUP_REMOTE:-phishlens-backup:}"
KEEP_DAYS="${PHISHLENS_BACKUP_KEEP_DAYS:-60}"
DATA_DIR="${PHISHLENS_DATA_DIR:-$HOME/phishlens_data}"
STAMP="$(date +%F)"
NAME="phishlens-backup-$STAMP.tar.gz"

if ! command -v rclone >/dev/null; then
    echo "rclone is not installed (https://rclone.org/install/)." >&2
    exit 1
fi
if [ "${1:-}" = "--list" ]; then
    rclone lsl "$REMOTE"
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/phishlens-backup-$STAMP"
mkdir -p "$STAGE/config" "$STAGE/data"

echo "[$(date '+%F %T')] backup start"

# 1. configuration
for f in "$HOME/.phishlens.env" "$HOME/Caddyfile"; do
    if [ -f "$f" ]; then cp -p "$f" "$STAGE/config/"; fi
done

# 2. backend data (consistent SQLite copies, plain copy for the rest)
if [ -d "$DATA_DIR" ]; then
    (cd "$DATA_DIR" && find . -type f) | while read -r rel; do
        src="$DATA_DIR/${rel#./}"
        dst="$STAGE/data/${rel#./}"
        mkdir -p "$(dirname "$dst")"
        case "$src" in
            *.db|*.sqlite|*.sqlite3)
                python3 -c 'import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close(); s.close()' "$src" "$dst" 2>/dev/null \
                    || cp -p "$src" "$dst" ;;
            *-wal|*-shm|*-journal) ;;          # covered by the backup API
            *) cp -p "$src" "$dst" ;;
        esac
    done
fi

# 3. web-server access logs (inside the Caddy container's volume)
docker exec caddy sh -c 'cd /data && [ -d logs ] && tar -cf - logs' > "$STAGE/caddy-logs.tar" 2>/dev/null || rm -f "$STAGE/caddy-logs.tar"

tar -czf "$WORK/$NAME" -C "$WORK" "phishlens-backup-$STAMP"
SIZE="$(du -h "$WORK/$NAME" | cut -f1)"

rclone copy "$WORK/$NAME" "$REMOTE"
rclone delete --min-age "${KEEP_DAYS}d" "$REMOTE"

echo "[$(date '+%F %T')] backup done: $NAME ($SIZE), backups older than $KEEP_DAYS days removed"
