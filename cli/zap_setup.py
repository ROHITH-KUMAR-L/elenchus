"""Local ZAP key storage and on-demand Compose startup."""

from __future__ import annotations

import os
import secrets
import stat
import subprocess
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from urllib.parse import urlsplit

from producers.dast.zap_runner import ZapApi

_ZAP_START_TIMEOUT_SECONDS = 90
_ZAP_POLL_INTERVAL_SECONDS = 0.5


def load_or_create_zap_api_key(
    configured_key: str | None = None,
    *,
    key_path: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> str:
    if configured_key:
        return configured_key
    environment = os.environ if environ is None else environ
    environment_key = environment.get("ZAP_API_KEY")
    if environment_key:
        return environment_key

    path = key_path or Path.home() / ".elenchus" / "zap.key"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError(f"ZAP key directory must not be a symlink: {path.parent}")
    if os.name == "posix":
        path.parent.chmod(0o700)

    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        deadline = time.monotonic() + 1
        while True:
            try:
                return _read_key_file(path)
            except ValueError as error:
                if "file is empty" not in str(error) or time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)

    key = secrets.token_urlsafe(32)
    handle = os.fdopen(descriptor, "w", encoding="utf-8")
    try:
        if os.name == "posix":
            os.fchmod(handle.fileno(), 0o600)
        handle.write(key)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
    except OSError:
        handle.close()
        path.unlink(missing_ok=True)
        raise
    return key


def _read_key_file(path: Path) -> str:
    path_metadata = path.lstat()
    if not stat.S_ISREG(path_metadata.st_mode):
        raise ValueError(f"ZAP API key must be a regular file: {path}")
    if os.name == "posix" and stat.S_IMODE(path_metadata.st_mode) != 0o600:
        path.chmod(0o600)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"ZAP API key must be a regular file: {path}")
        key = handle.read().strip()
    if not key:
        raise ValueError(f"ZAP API key file is empty: {path}")
    return key


def ensure_zap_api_available(
    api: ZapApi,
    api_url: str,
    api_key: str,
    *,
    compose_file: Path | None = None,
    environ: Mapping[str, str] | None = None,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    try:
        _verify_api(api)
        return
    except RuntimeError as error:
        if _is_auth_failure(error):
            raise _credentials_error() from error
        if "cannot reach the local ZAP API" not in str(error):
            raise RuntimeError(f"could not verify the local ZAP API: {error}") from error

    file_path = compose_file or Path(__file__).resolve().parents[1] / "infra" / "zap.compose.yaml"
    _start_compose_zap(file_path, api_url, api_key, environ=environ, run=run)

    deadline = monotonic() + _ZAP_START_TIMEOUT_SECONDS
    last_error: RuntimeError | None = None
    while monotonic() < deadline:
        try:
            _verify_api(api)
            return
        except RuntimeError as error:
            if _is_auth_failure(error):
                raise _credentials_error() from error
            if not _is_startup_transient(error):
                raise RuntimeError(f"could not verify the local ZAP API: {error}") from error
            last_error = error
            sleep(_ZAP_POLL_INTERVAL_SECONDS)
    raise RuntimeError(
        "ZAP did not become ready before the startup timeout; check the local "
        "elenchus-zap Compose service"
    ) from last_error


def _verify_api(api: ZapApi) -> None:
    response = api.call("core", "view", "version")
    if not isinstance(response.get("version"), str):
        raise RuntimeError("ZAP returned an invalid version response")


def _is_auth_failure(error: RuntimeError) -> bool:
    return "returned HTTP 401" in str(error) or "returned HTTP 403" in str(error)


def _is_startup_transient(error: RuntimeError) -> bool:
    message = str(error)
    if "cannot reach the local ZAP API" in message or "timed out" in message:
        return True
    for status in range(500, 600):
        if f"returned HTTP {status}" in message:
            return True
    return False


def _credentials_error() -> RuntimeError:
    return RuntimeError(
        "the local ZAP API rejected its key. If ZAP was started with a different "
        "key, stop that service and rerun elenchus so it can start ZAP with the "
        "saved key, or set ZAP_API_KEY to the existing service key."
    )


def _start_compose_zap(
    compose_file: Path,
    api_url: str,
    api_key: str,
    *,
    environ: Mapping[str, str] | None,
    run: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    if not compose_file.is_file():
        raise RuntimeError(f"the pinned ZAP Compose file is unavailable: {compose_file}")
    environment = dict(os.environ if environ is None else environ)
    environment["ZAP_API_KEY"] = api_key
    port = urlsplit(api_url).port or 80
    environment["ZAP_PORT"] = str(port)
    try:
        result = run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d"],
            cwd=compose_file.parent.parent,
            env=environment,
            capture_output=True,
            text=True,
            timeout=_ZAP_START_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError("starting ZAP automatically requires Docker Compose") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Docker Compose timed out while starting the local ZAP service") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").replace(api_key, "[redacted]").strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"Docker Compose could not start the local ZAP service{suffix}")
