"""Explicit privilege separation helpers for Linux service startup."""

from __future__ import annotations

import grp
import os
import pwd


class PrivilegeDropError(RuntimeError):
    """Raised when the process cannot enter the configured unprivileged identity."""


def drop_privileges(username: str = "bastionfw", groupname: str | None = None) -> None:
    """Drop supplementary groups, group ID, and user ID permanently.

    Call this only after privileged resources have been opened. The operation is
    intentionally irreversible for the current process and refuses to proceed
    when the target identity is missing or the process is not root.
    """
    if os.getuid() != 0:
        raise PrivilegeDropError("privilege drop requires a root process")
    try:
        user = pwd.getpwnam(username)
        group = grp.getgrnam(groupname or username)
    except KeyError as exc:
        raise PrivilegeDropError("configured service identity does not exist") from exc
    try:
        os.initgroups(user.pw_name, group.gr_gid)
        os.setgid(group.gr_gid)
        os.setuid(user.pw_uid)
    except OSError as exc:
        raise PrivilegeDropError("failed to drop process privileges") from exc
    if os.getuid() == 0 or os.getgid() == 0:
        raise PrivilegeDropError("process still has root identity after privilege drop")
