import asyncio
import os
import hashlib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Callable


@dataclass
class FileScanResult:
    filename: str
    path: Path
    sha256: Optional[str] = None
    name: Optional[str] = None
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    severity: Optional[str] = None
    label: Optional[str] = None
    file_type: Optional[str] = None
    sandbox: Optional[str] = None
    result: Optional[str] = None
    error: Optional[str] = None
    gemini: Optional[str] = None


    def __str__(self):
        base = f"""
=== {self.filename} ===
Path: {self.path}
SHA256: {self.sha256}
"""

        if self.error:
            return base + f"""ERROR: {self.error}
"""

        out = base
        if self.result:
            out += f"""Result: {self.result}
"""
        if self.name:
            out += f"""Name: {self.name}
"""
        if self.malicious or self.suspicious or self.undetected:
            out += f"""Detections: {self.malicious} malicious | {self.suspicious} suspicious | {self.undetected} undetected
"""
        if self.severity:
            out += f"""Severity: {self.severity}
"""
        if self.label:
            out += f"""Label: {self.label}
"""
        if self.file_type:
            out += f"""Type: {self.file_type}
"""
        if self.sandbox:
            out += f"""Sandbox: {self.sandbox}
"""
        if self.gemini:
            out += f"""Gemini: {self.gemini}
"""

        return out


def sha256_of_file(path, chunk_size=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):  # chunked reading = safe for big files
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ArchiveLimits:
    max_files: int = 5000
    max_mb: int = 500 * 1024 * 1024
    max_depth: int = 2


ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz"}
ARCHIVE_MULTI_EXTENSIONS = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst")


def find_7z() -> Optional[str]:
    candidates = [
        shutil.which("7z"),
        shutil.which("7z.exe"),
        shutil.which("7za"),
        shutil.which("7za.exe"),
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]

    for path in candidates:
        if path and os.path.exists(path):
            return path

    return None


def ensure_7z_available() -> str:
    seven_zip = find_7z()
    if not seven_zip:
        raise RuntimeError("7-Zip CLI not found. Install 7-Zip and ensure 7z is on PATH.")
    return seven_zip


def is_archive_path(path: Path) -> bool:
    name = path.name.lower()
    if any(name.endswith(ext) for ext in ARCHIVE_MULTI_EXTENSIONS):
        return True
    return path.suffix.lower() in ARCHIVE_EXTENSIONS


def _parse_7z_slt_output(text: str) -> list[dict[str, str]]:
    blocks = []
    block: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if block:
                blocks.append(block)
                block = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            block[key.strip()] = value.strip()
    if block:
        blocks.append(block)
    return blocks


def _list_archive_entries(archive_path: Path, seven_zip_path: str) -> list[dict[str, str]]:
    cmd = [seven_zip_path, "l", "-slt", str(archive_path)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"7-Zip listing failed: {msg or 'unknown error'}")
    return _parse_7z_slt_output(result.stdout)


def _archive_file_entries(archive_path: Path, seven_zip_path: str) -> list[dict[str, str]]:
    entries = []
    blocks = _list_archive_entries(archive_path, seven_zip_path)
    for block in blocks:
        if "Path" not in block:
            continue
        if "Folder" not in block and "Attributes" not in block:
            continue
        if block.get("Folder", "-") == "+":
            continue
        if "D" in block.get("Attributes", ""):
            continue
        if block.get("Encrypted", "-") == "+":
            raise RuntimeError("Archive is encrypted.")
        entries.append(block)
    return entries


def _hash_file(path: Path, display_path: Optional[str] = None) -> FileScanResult:
    display = display_path or str(path)
    try:
        sha = sha256_of_file(path)
        return FileScanResult(filename=path.name, path=Path(display), sha256=sha)
    except Exception as e:
        return FileScanResult(filename=path.name, path=Path(display), error=str(e))


def _process_archive(
    archive_path: Path,
    include_archives: bool,
    archive_limits: ArchiveLimits,
    seven_zip_path: str,
    depth: int = 0,
    display_path: Optional[str] = None,
):
    display = display_path or str(archive_path)
    try:
        entries = _archive_file_entries(archive_path, seven_zip_path)
        if len(entries) > archive_limits.max_files:
            raise RuntimeError(
                f"Archive contains too many files ({len(entries)} > {archive_limits.max_files})."
            )
        total_size = 0
        for entry in entries:
            try:
                total_size += int(entry.get("Size", "0") or 0)
            except ValueError:
                pass
        if total_size > archive_limits.max_mb:
            raise RuntimeError(
                f"Archive expanded size too large ({round(total_size / (1024 * 1024), 2)} > {round(archive_limits.max_mb / (1024 * 1024), 2)} MB)."
            )
    except Exception as e:
        yield FileScanResult(filename=archive_path.name, path=Path(display), error=str(e))
        return

    with tempfile.TemporaryDirectory(prefix="vt_archive_") as tmpdir:
        cmd = [seven_zip_path, "x", "-y", f"-o{tmpdir}", str(archive_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            msg = (result.stderr or result.stdout).strip()
            yield FileScanResult(
                filename=archive_path.name,
                path=Path(display),
                error=f"7-Zip extraction failed: {msg or 'unknown error'}",
            )
            return

        for root, _, files in os.walk(tmpdir):
            for name in files:
                file_path = Path(root) / name
                rel = os.path.relpath(file_path, tmpdir)
                entry_display = f"{display}::{rel}"
                if include_archives and is_archive_path(file_path) and depth < archive_limits.max_depth:
                    yield from _process_archive(
                        file_path,
                        include_archives,
                        archive_limits,
                        seven_zip_path,
                        depth=depth + 1,
                        display_path=entry_display,
                    )
                else:
                    yield _hash_file(file_path, display_path=entry_display)


def walk_and_hash(
    base_path: Path,
    include_archives: bool = False,
    archive_limits: Optional[ArchiveLimits] = None,
    seven_zip_path: Optional[str] = None,
):
    if archive_limits is None:
        archive_limits = ArchiveLimits()
    if include_archives and not seven_zip_path:
        seven_zip_path = ensure_7z_available()

    for entry in os.scandir(base_path):
        if entry.is_dir(follow_symlinks=False):
            yield from walk_and_hash(
                Path(entry.path),
                include_archives=include_archives,
                archive_limits=archive_limits,
                seven_zip_path=seven_zip_path,
            )
        elif entry.is_file(follow_symlinks=False):
            file_path = Path(entry.path)
            if is_archive_path(file_path) and not include_archives:
                yield FileScanResult(
                    filename=file_path.name,
                    path=file_path,
                    error="Archive not scanned.",
                )
            elif include_archives and is_archive_path(file_path):
                yield from _process_archive(
                    file_path,
                    include_archives,
                    archive_limits,
                    seven_zip_path,
                    depth=0,
                )
            else:
                yield _hash_file(file_path)


def _process_archive_list(
    archive_path: Path,
    include_archives: bool,
    archive_limits: ArchiveLimits,
    seven_zip_path: str,
    depth: int = 0,
    display_path: Optional[str] = None,
) -> list[FileScanResult]:
    return list(
        _process_archive(
            archive_path,
            include_archives,
            archive_limits,
            seven_zip_path,
            depth=depth,
            display_path=display_path,
        )
    )


def _iter_hash_jobs(
    base_path: Path,
    include_archives: bool,
    archive_limits: ArchiveLimits,
    seven_zip_path: Optional[str],
):
    for entry in os.scandir(base_path):
        if entry.is_dir(follow_symlinks=False):
            yield from _iter_hash_jobs(
                Path(entry.path),
                include_archives=include_archives,
                archive_limits=archive_limits,
                seven_zip_path=seven_zip_path,
            )
        elif entry.is_file(follow_symlinks=False):
            file_path = Path(entry.path)
            if is_archive_path(file_path) and not include_archives:
                yield (
                    "result",
                    FileScanResult(
                        filename=file_path.name,
                        path=file_path,
                        error="Archive not scanned.",
                    ),
                )
            elif include_archives and is_archive_path(file_path):
                yield ("archive", file_path)
            else:
                yield ("file", file_path)


async def _run_hash_job(
    semaphore: asyncio.Semaphore,
    func,
    *args,
):
    async with semaphore:
        return await asyncio.to_thread(func, *args)


async def walk_and_hash_async(
    base_path: Path,
    include_archives: bool = False,
    archive_limits: Optional[ArchiveLimits] = None,
    seven_zip_path: Optional[str] = None,
    max_concurrency: int = 4,
    progress_cb: Optional[Callable[[], None]] = None,
) -> list[FileScanResult]:
    if archive_limits is None:
        archive_limits = ArchiveLimits()
    if include_archives and not seven_zip_path:
        seven_zip_path = ensure_7z_available()

    max_concurrency = max(1, max_concurrency)
    semaphore = asyncio.Semaphore(max_concurrency)
    tasks: list[asyncio.Task] = []
    results: list[FileScanResult] = []

    for kind, payload in _iter_hash_jobs(
        base_path,
        include_archives=include_archives,
        archive_limits=archive_limits,
        seven_zip_path=seven_zip_path,
    ):
        if kind == "result":
            results.append(payload)
            if progress_cb:
                progress_cb()
            continue

        if kind == "archive":
            tasks.append(
                asyncio.create_task(
                    _run_hash_job(
                        semaphore,
                        _process_archive_list,
                        payload,
                        include_archives,
                        archive_limits,
                        seven_zip_path,
                        0,
                        None,
                    )
                )
            )
            continue

        tasks.append(
            asyncio.create_task(
                _run_hash_job(semaphore, _hash_file, payload, None)
            )
        )

    for task in asyncio.as_completed(tasks):
        updated = await task
        if isinstance(updated, list):
            for item in updated:
                results.append(item)
                if progress_cb:
                    progress_cb()
        else:
            results.append(updated)
            if progress_cb:
                progress_cb()

    return results


def count_files(
    base_path: Path,
    include_archives: bool = False,
    archive_limits: Optional[ArchiveLimits] = None,
    seven_zip_path: Optional[str] = None,
) -> int:
    count = 0
    if archive_limits is None:
        archive_limits = ArchiveLimits()
    if include_archives and not seven_zip_path:
        seven_zip_path = ensure_7z_available()

    for entry in os.scandir(base_path):
        if entry.is_dir(follow_symlinks=False):
            count += count_files(
                Path(entry.path),
                include_archives=include_archives,
                archive_limits=archive_limits,
                seven_zip_path=seven_zip_path,
            )
        elif entry.is_file(follow_symlinks=False):
            file_path = Path(entry.path)
            if include_archives and is_archive_path(file_path):
                try:
                    entries = _archive_file_entries(file_path, seven_zip_path)
                    count += max(len(entries), 1)
                except Exception:
                    count += 1
            else:
                count += 1
    return count
