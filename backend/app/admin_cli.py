"""Police Portal account administration (run on the server).

    python -m backend.app.admin_cli create-user --username alice --role admin
    python -m backend.app.admin_cli set-password --username alice
    python -m backend.app.admin_cli disable --username alice
    python -m backend.app.admin_cli list

Passwords are read interactively (getpass) or from stdin with --password-stdin;
they are never accepted as command-line arguments (shell history / process list).
"""
from __future__ import annotations

import argparse
import getpass
import sys

from . import security
from .config import Settings
from .db.repo import Repository


def _password(args) -> str:
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("New password (min 12 chars): ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("passwords do not match")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="admin_cli", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("create-user", "set-password"):
        p = sub.add_parser(name)
        p.add_argument("--username", required=True)
        p.add_argument("--password-stdin", action="store_true")
        if name == "create-user":
            p.add_argument("--role", choices=security.ROLES, default="viewer")
    p = sub.add_parser("disable")
    p.add_argument("--username", required=True)
    sub.add_parser("list")
    args = parser.parse_args(argv)

    repo = Repository(Settings.from_env())
    repo.initialize()
    try:
        if args.cmd == "list":
            for user in repo.list_users():
                print(f"{user['username']:24} {user['role']:13} {'active' if user['active'] else 'disabled'}")
            return 0
        username = args.username.strip().lower()
        if args.cmd == "disable":
            ok = repo.set_user_active(username, False)
            repo.audit(username="cli", action="admin.user.active", target=username, detail={"active": False})
            print("disabled" if ok else "no such user")
            return 0 if ok else 1
        try:
            hashed = security.hash_password(_password(args))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.cmd == "create-user":
            if repo.get_user(username):
                print("error: user already exists", file=sys.stderr)
                return 1
            repo.create_user(username, hashed, args.role)
            repo.audit(username="cli", action="admin.user.create", target=username, detail={"role": args.role})
            print(f"created {username} ({args.role})")
        else:
            ok = repo.set_user_password(username, hashed)
            repo.audit(username="cli", action="admin.user.password", target=username)
            print("password updated; existing sessions revoked" if ok else "no such user")
            return 0 if ok else 1
        return 0
    finally:
        repo.close()


if __name__ == "__main__":
    raise SystemExit(main())
