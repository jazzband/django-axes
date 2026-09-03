import argparse
import os
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


QUERY = """
    SELECT auth_user.username, fakeaccountapp_loginlog.ip_address
    FROM fakeaccountapp_loginlog
    JOIN auth_user ON auth_user.id = fakeaccountapp_loginlog.user_id
    ORDER BY auth_user.username, fakeaccountapp_loginlog.ip_address
    """


def collect_users(rows):
    users = defaultdict(lambda: {"ips": set(), "logins": 0})
    for username, ip_address in rows:
        users[username]["ips"].add(ip_address)
        users[username]["logins"] += 1
    return users


def load_users(database_path):
    with sqlite3.connect(database_path) as connection:
        return collect_users(connection.execute(QUERY))


def load_postgres_users():
    sys.path.insert(0, str(PROJECT_ROOT))
    import django
    from django.db import connections

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fakeaccount.settings")
    django.setup()
    connection = connections["default"]
    with connection.cursor() as cursor:
        cursor.execute(QUERY)
        return collect_users(cursor.fetchall())


def print_group(title, users, multiple):
    print(title)
    matching = [
        (username, details)
        for username, details in sorted(users.items())
        if (len(details["ips"]) > 1) == multiple
    ]
    if not matching:
        print("  (brak)")
        return
    for username, details in matching:
        ips = ", ".join(sorted(details["ips"]))
        print(f"  {username}: {ips} ({details['logins']} logowan)")


def print_report(database_label, users):
    print(f"Baza: {database_label}")
    print_group("Uzytkownicy zalogowani z jednego IP", users, False)
    print_group("Uzytkownicy zalogowani z wiecej niz jednego IP", users, True)


def main():
    parser = argparse.ArgumentParser(description="Raport uzytkownikow Django wedlug adresow IP.")
    parser.add_argument(
        "database",
        nargs="?",
        type=Path,
        help="Sciezka do bazy SQLite; jej podanie wybiera tylko SQLite",
    )
    database_group = parser.add_mutually_exclusive_group()
    database_group.add_argument(
        "--postgres",
        action="store_true",
        help="Pobierz dane z bazy PostgreSQL skonfigurowanej w Django",
    )
    database_group.add_argument(
        "--sqlite",
        action="store_true",
        help="Pobierz dane tylko z bazy SQLite (domyslnie raportowane sa obie bazy)",
    )
    args = parser.parse_args()

    if args.postgres:
        if args.database:
            parser.error("Nie mozna laczyc --postgres ze sciezka do bazy SQLite")
        print_report("PostgreSQL (Django: default)", load_postgres_users())
        return

    if args.database or args.sqlite:
        database_path = args.database or PROJECT_ROOT / "db.sqlite3"
        if not database_path.exists():
            parser.error(f"Baza nie istnieje: {database_path}")
        print_report(str(database_path), load_users(database_path))
        return

    database_path = PROJECT_ROOT / "db.sqlite3"
    if not database_path.exists():
        parser.error(f"Baza nie istnieje: {database_path}")
    print_report(str(database_path), load_users(database_path))
    print_report("PostgreSQL (Django: default)", load_postgres_users())


if __name__ == "__main__":
    main()