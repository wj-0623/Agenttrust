"""Offline schema/seed/RLS migrator; do not give the API migration credentials."""
from .config import settings
from .db import Database


def main() -> None:
    target = settings.migration_database_url or settings.database_url or settings.database_path
    Database(target, postgres_rls_enabled=settings.postgres_rls_enabled,
             postgres_app_role=settings.postgres_app_role).initialize()
    print("AgentTrust migration 0005_security_saas applied")


if __name__ == "__main__":
    main()
