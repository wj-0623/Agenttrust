import os
from pathlib import Path

password = os.environ["POSTGRES_APP_PASSWORD"]
if any(character in password for character in ("\n", "\r", "\x00")):
    raise ValueError("Invalid pool credential")
os.umask(0o077)
Path("/tmp/agenttrust-users.txt").write_text(
    '"agenttrust_app" "' + password.replace('"', '""') + '"\n', encoding="utf-8"
)
os.execvp("pgbouncer", ["pgbouncer", "/etc/pgbouncer/agenttrust.ini"])
