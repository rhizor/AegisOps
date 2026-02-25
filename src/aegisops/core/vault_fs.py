from __future__ import annotations

import json
import os
import socket
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

IS_WINDOWS = os.name == "nt"


def set_secure_umask() -> None:
    """Best-effort: on POSIX ensure new files/dirs default to user-only."""
    if not IS_WINDOWS:
        os.umask(0o077)


def ensure_dir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def ensure_file_mode(path: Path, mode: int = 0o600) -> None:
    if IS_WINDOWS:
        return
    if path.exists():
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def _fsync_fileobj(f) -> None:
    f.flush()
    os.fsync(f.fileno())


def fsync_dir(dir_path: Path) -> None:
    """POSIX durability for directory entry updates (rename)."""
    if IS_WINDOWS:
        return
    fd = os.open(str(dir_path), os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        _fsync_fileobj(f)
    os.replace(tmp, path)
    ensure_file_mode(path)
    if not IS_WINDOWS:
        fsync_dir(path.parent)


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    atomic_write_bytes(path, text.encode(encoding))


def dump_canonical_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def safe_case_path(case_root: Path, rel: str | Path) -> Path:
    """Resolve rel against case_root; reject traversal/absolute paths."""
    case_root = case_root.resolve()
    relp = Path(rel)
    if relp.is_absolute():
        raise ValueError("Absolute paths are not allowed")
    candidate = (case_root / relp).resolve()
    try:
        candidate.relative_to(case_root)
    except ValueError:
        raise ValueError("Path traversal detected")
    return candidate


@contextmanager
def acquire_case_lock(case_root: Path, timeout_s: int = 10) -> Iterator[None]:
    ensure_dir(case_root)
    lock_path = case_root / ".case.lock"
    deadline = time.time() + timeout_s
    payload = {
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "created_at": int(time.time()),
    }
    data = dump_canonical_json(payload).encode("utf-8")

    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            ensure_file_mode(lock_path)
            break
        except FileExistsError:
            if time.time() >= deadline:
                raise TimeoutError(f"Could not acquire lock: {lock_path}")
            time.sleep(0.1)

    try:
        yield
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass
