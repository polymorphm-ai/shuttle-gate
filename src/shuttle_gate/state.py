"""Crash-consistent persistent-state generations and cross-process locking."""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import stat
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .errors import StateError
from .files import InstancePaths, atomic_write_json, ensure_private_directory, fsync_directory

STATE_SCHEMA_VERSION = 1
LOCK_FILE = ".state.lock"
GENERATIONS_DIR = "generations"
CURRENT_LINK = "current"
MANIFEST_FILE = "manifest.json"
LEGACY_DATA_DIRECTORIES = ("server", "peers")
GENERATION_PATTERN = re.compile(r"^gen-[0-9a-f]{32}$")
STAGING_PATTERN = re.compile(r"^\.staging-[0-9a-f]{32}$")
TEMPORARY_CURRENT_PATTERN = re.compile(r"^\.current-gen-[0-9a-f]{32}$")
MAX_MANIFEST_BYTES = 64 * 1024
OPERATION_SCHEMA_VERSION = 1
OPERATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
OPERATION_KIND_PATTERN = re.compile(r"^[a-z][a-z0-9.-]{0,127}$")

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]


@dataclass(frozen=True)
class StateView:
    """One validated, stable persistent-state generation."""

    paths: InstancePaths
    generation: str | None


@dataclass(frozen=True)
class StateOperation[T]:
    """Typed idempotency receipt published with a state mutation."""

    request_id: str
    kind: str
    encode: Callable[[T], JsonValue]
    decode: Callable[[JsonValue], T]

    def __post_init__(self) -> None:
        if OPERATION_ID_PATTERN.fullmatch(self.request_id) is None:
            raise StateError("operation ID must be 1-128 safe ASCII characters")
        if OPERATION_KIND_PATTERN.fullmatch(self.kind) is None:
            raise StateError("operation kind is invalid")


@dataclass(frozen=True)
class _CompletedOperation[T]:
    value: T


def void_operation(request_id: str, kind: str) -> StateOperation[None]:
    """Build an idempotency receipt for a mutation with no return value."""

    def encode(_value: None) -> JsonValue:
        return None

    def decode(value: JsonValue) -> None:
        if value is not None:
            raise StateError("completed operation has an invalid result")

    return StateOperation(request_id=request_id, kind=kind, encode=encode, decode=decode)


def _lock_descriptor(paths: InstancePaths, *, create: bool) -> int:
    if create:
        ensure_private_directory(paths.state)
    flags = os.O_CLOEXEC | os.O_NOFOLLOW | (os.O_RDWR | os.O_CREAT if create else os.O_RDONLY)
    try:
        descriptor = os.open(paths.state / LOCK_FILE, flags, 0o600)
    except FileNotFoundError as exc:
        raise StateError("persistent state is not initialized") from exc
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise StateError("persistent-state lock must be a regular file")
    if create:
        os.fchmod(descriptor, 0o600)
    return descriptor


@contextmanager
def state_lock(
    paths: InstancePaths,
    *,
    exclusive: bool,
    blocking: bool = True,
) -> Iterator[None]:
    """Serialize writers and provide stable snapshots to readers."""

    descriptor = _lock_descriptor(paths, create=exclusive)
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    if not blocking:
        operation |= fcntl.LOCK_NB
    try:
        try:
            fcntl.flock(descriptor, operation)
        except BlockingIOError as exc:
            raise StateError(
                "persistent state is busy; stop the gateway or wait for the active operation"
            ) from exc
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _read_manifest(root: Path, expected_generation: str) -> None:
    manifest = root / MANIFEST_FILE
    try:
        info = manifest.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            raise StateError(f"invalid state manifest: {manifest}")
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise StateError(f"state generation is incomplete: {root}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateError(f"cannot read state manifest {manifest}: {exc}") from exc
    if value != {"generation": expected_generation, "schema_version": STATE_SCHEMA_VERSION}:
        raise StateError(f"state manifest does not match generation: {root}")


def _active_generation(paths: InstancePaths, *, required: bool) -> tuple[Path, str] | None:
    current = paths.state / CURRENT_LINK
    try:
        info = current.lstat()
    except FileNotFoundError:
        if required:
            if _legacy_state_present(paths):
                raise StateError("legacy key state requires migration; run keys generate") from None
            raise StateError("persistent keys are not initialized; run keys generate") from None
        return None
    if not stat.S_ISLNK(info.st_mode):
        raise StateError(f"persistent-state pointer must be a symlink: {current}")
    target = os.readlink(current)
    target_path = Path(target)
    if (
        target_path.is_absolute()
        or len(target_path.parts) != 2
        or target_path.parts[0] != GENERATIONS_DIR
        or GENERATION_PATTERN.fullmatch(target_path.parts[1]) is None
    ):
        raise StateError(f"invalid persistent-state pointer: {current}")
    generation = target_path.parts[1]
    root = paths.state / target_path
    try:
        root_info = root.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise StateError(f"persistent-state pointer is broken: {current}") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise StateError(f"state generation must be a directory: {root}")
    _read_manifest(root, generation)
    return root, generation


def _legacy_state_present(paths: InstancePaths) -> bool:
    for name in LEGACY_DATA_DIRECTORIES:
        try:
            (paths.state / name).lstat()
        except FileNotFoundError:
            continue
        return True
    return False


@contextmanager
def locked_state_view(
    paths: InstancePaths,
    *,
    required: bool = True,
    exclusive: bool = False,
    blocking: bool = True,
) -> Iterator[StateView]:
    """Hold a lock while using one active generation."""

    if paths.data is not None:
        yield StateView(paths=paths, generation=paths.data.name)
        return
    if not (paths.state / LOCK_FILE).exists() and not required:
        with state_lock(paths, exclusive=True, blocking=False):
            pass
    with state_lock(paths, exclusive=exclusive, blocking=blocking):
        active = _active_generation(paths, required=required)
        if active is None:
            if _legacy_state_present(paths):
                raise StateError("legacy key state requires migration; run keys generate")
            yield StateView(paths=paths.with_data(paths.state / CURRENT_LINK), generation=None)
        else:
            root, generation = active
            yield StateView(paths=paths.with_data(root), generation=generation)


def read_state[T](
    paths: InstancePaths,
    reader: Callable[[InstancePaths], T],
    *,
    required: bool = True,
) -> T:
    """Read a complete generation under a shared lock."""

    with locked_state_view(paths, required=required) as view:
        return reader(view.paths)


def _remove_owned(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        shutil.rmtree(path)
    else:
        path.unlink()


def _clean_incomplete(paths: InstancePaths) -> None:
    generations = paths.state / GENERATIONS_DIR
    if generations.is_dir():
        for child in generations.iterdir():
            if STAGING_PATTERN.fullmatch(child.name) is not None:
                with suppress(OSError):
                    _remove_owned(child)
    for child in paths.state.glob(".current-*"):
        if TEMPORARY_CURRENT_PATTERN.fullmatch(child.name) is None:
            raise StateError(f"unexpected persistent-state object: {child}")
        with suppress(OSError):
            _remove_owned(child)


def _clean_unreferenced_generations(paths: InstancePaths, active: Path | None) -> None:
    generations = paths.state / GENERATIONS_DIR
    if not generations.is_dir():
        return
    for child in generations.iterdir():
        if child == active:
            continue
        if GENERATION_PATTERN.fullmatch(child.name) is None:
            raise StateError(f"unexpected object in generations directory: {child}")
        with suppress(OSError):
            _remove_owned(child)
    with suppress(OSError):
        fsync_directory(generations)


def _copy_active(source: Path | None, destination: Path) -> None:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    if source is None:
        return
    for child in source.iterdir():
        if child.name == MANIFEST_FILE:
            continue
        target = destination / child.name
        info = child.lstat()
        if stat.S_ISDIR(info.st_mode):
            shutil.copytree(child, target, symlinks=True)
        elif stat.S_ISREG(info.st_mode):
            shutil.copy2(child, target, follow_symlinks=False)
        else:
            raise StateError(f"unexpected object in persistent state: {child}")


def _copy_legacy_state(paths: InstancePaths, destination: Path) -> None:
    for name in LEGACY_DATA_DIRECTORIES:
        source = paths.state / name
        try:
            info = source.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise StateError(f"legacy state must be a directory: {source}")
        shutil.copytree(source, destination / name, symlinks=True)


def _clean_legacy_state(paths: InstancePaths) -> None:
    for name in LEGACY_DATA_DIRECTORIES:
        legacy = paths.state / name
        try:
            info = legacy.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise StateError(f"refusing to remove unexpected legacy-state object: {legacy}")
        _remove_owned(legacy)
    fsync_directory(paths.state)


def _operation_path[T](root: Path, operation: StateOperation[T]) -> Path:
    digest = sha256(operation.request_id.encode("ascii")).hexdigest()
    return root / "operations" / f"{digest}.json"


def _json_value(value: object, label: str) -> JsonValue:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list):
        return [_json_value(item, label) for item in value]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return {key: _json_value(item, label) for key, item in value.items()}
    raise StateError(f"{label} is not valid JSON data")


def _read_operation[T](root: Path, operation: StateOperation[T]) -> _CompletedOperation[T] | None:
    path = _operation_path(root, operation)
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
        raise StateError(f"invalid operation receipt: {path}")
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateError(f"cannot read operation receipt {path}: {exc}") from exc
    value = _json_value(raw, "operation receipt")
    if not isinstance(value, dict) or (
        value.get("schema_version") != OPERATION_SCHEMA_VERSION
        or value.get("request_id") != operation.request_id
        or value.get("kind") != operation.kind
        or "result" not in value
    ):
        raise StateError(
            f"operation ID was already used for another request: {operation.request_id}"
        )
    return _CompletedOperation(operation.decode(value["result"]))


def _write_operation[T](root: Path, operation: StateOperation[T], result: T) -> None:
    path = _operation_path(root, operation)
    atomic_write_json(
        path,
        {
            "schema_version": OPERATION_SCHEMA_VERSION,
            "request_id": operation.request_id,
            "kind": operation.kind,
            "result": operation.encode(result),
        },
        0o600,
    )


def _fsync_tree(root: Path) -> None:
    directories: list[Path] = []
    for current, names, files in os.walk(root, topdown=True, followlinks=False):
        directory = Path(current)
        directories.append(directory)
        for name in [*names, *files]:
            path = directory / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (
                stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
            ):
                raise StateError(f"persistent state contains an unsafe object: {path}")
            if stat.S_ISREG(info.st_mode):
                descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
    for directory in reversed(directories):
        fsync_directory(directory)


def _publish(paths: InstancePaths, staging: Path, generation: str) -> Path:
    generations = paths.state / GENERATIONS_DIR
    final = generations / generation
    atomic_write_json(
        staging / MANIFEST_FILE,
        {"generation": generation, "schema_version": STATE_SCHEMA_VERSION},
        0o600,
    )
    _fsync_tree(staging)
    os.replace(staging, final)
    fsync_directory(generations)

    temporary_link = paths.state / f".current-{generation}"
    os.symlink(f"{GENERATIONS_DIR}/{generation}", temporary_link)
    fsync_directory(paths.state)
    os.replace(temporary_link, paths.state / CURRENT_LINK)
    fsync_directory(paths.state)
    return final


def _clean_old_generations(paths: InstancePaths, active: Path) -> None:
    generations = paths.state / GENERATIONS_DIR
    for child in generations.iterdir():
        if child == active:
            continue
        if GENERATION_PATTERN.fullmatch(child.name) is None:
            raise StateError(f"unexpected object in generations directory: {child}")
        with suppress(OSError):
            _remove_owned(child)
    with suppress(OSError):
        fsync_directory(generations)


def mutate_state[T](
    paths: InstancePaths,
    mutator: Callable[[InstancePaths], T],
    validator: Callable[[InstancePaths], None],
    *,
    publish_if: Callable[[T], bool] | None = None,
    operation: StateOperation[T] | None = None,
) -> T:
    """Build, validate, and atomically publish one complete state generation."""

    with state_lock(paths, exclusive=True, blocking=False):
        ensure_private_directory(paths.state / GENERATIONS_DIR)
        _clean_incomplete(paths)
        active = _active_generation(paths, required=False)
        _clean_unreferenced_generations(paths, active[0] if active is not None else None)
        if active is not None and operation is not None:
            completed = _read_operation(active[0], operation)
            if completed is not None:
                validator(paths.with_data(active[0]))
                _clean_legacy_state(paths)
                return completed.value
        generation = f"gen-{uuid.uuid4().hex}"
        staging = paths.state / GENERATIONS_DIR / f".staging-{generation[4:]}"
        final: Path | None = None
        try:
            _copy_active(active[0] if active is not None else None, staging)
            if active is None:
                _copy_legacy_state(paths, staging)
            staged_paths = paths.with_data(staging)
            result = mutator(staged_paths)
            if publish_if is not None and not publish_if(result):
                _remove_owned(staging)
                return result
            if operation is not None:
                _write_operation(staging, operation, result)
            validator(staged_paths)
            final = _publish(paths, staging, generation)
            published = _active_generation(paths, required=True)
            if published is None or published[0] != final:
                raise StateError("persistent-state publication could not be verified")
            validator(paths.with_data(final))
        except BaseException:
            with suppress(OSError):
                _remove_owned(staging)
            if final is not None and not (paths.state / CURRENT_LINK).exists():
                with suppress(OSError):
                    _remove_owned(final)
            raise
        if final is None:
            raise StateError("persistent-state publication did not produce a generation")
        _clean_old_generations(paths, final)
        _clean_legacy_state(paths)
        return result
