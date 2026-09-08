#!/bin/sh
set -eu
umask 077
backup_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
target="/backups/full-$backup_id"
pg_basebackup --pgdata="$target" --format=plain --wal-method=stream --checkpoint=fast --no-clean
pg_verifybackup "$target"
pg_dump --format=custom --file="/backups/logical-$backup_id.dump"
pg_restore --list "/backups/logical-$backup_id.dump" > "/backups/logical-$backup_id.manifest"
echo "Verified physical and logical backup: $backup_id; restore drill is still required"
