import tarfile
import time
import zipfile
from pathlib import Path
from typing import List, Tuple

import requests
from pyxnat import Interface


def _is_zip(archive: Path) -> bool:
    return archive.suffix.lower() == ".zip"


def _is_tar(archive: Path) -> bool:
    name = archive.name.lower()
    return (
        archive.suffix.lower() == ".tar"
        or name.endswith(".tar.gz")
        or archive.suffix.lower() == ".tgz"
    )


def archive_members(archive: Path) -> List[str]:
    if _is_zip(archive):
        with zipfile.ZipFile(archive) as zf:
            return zf.namelist()
    if _is_tar(archive):
        with tarfile.open(archive) as tf:
            return tf.getnames()
    raise ValueError(
        f"Unsupported archive format {archive.suffix} (name: {archive.name})"
    )


def archive_read(archive: Path, member: str) -> bytes:
    if _is_zip(archive):
        with zipfile.ZipFile(archive) as zf:
            return zf.read(member)
    if _is_tar(archive):
        with tarfile.open(archive) as tf:
            f = tf.extractfile(member)
            if f is None:
                raise ValueError(f"{member} is a directory, not a file")
            return f.read()
    raise ValueError(
        f"Unsupported archive format {archive.suffix} (name: {archive.name})"
    )


def download_file(url: str, filename: str):
    with open(filename, "wb") as f:
        with requests.get(url, stream=True) as r:
            if r.status_code != 200:
                r.raise_for_status()

            total_length = int(r.headers.get("content-length", 0))
            print(f"Starting download: {filename}")
            print(f"Total file size: {total_length / (1024 * 1024):.2f} MB")

            downloaded = 0
            start_time = time.time()

            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue

                f.write(chunk)
                downloaded += len(chunk)

                elapsed_time = time.time() - start_time
                speed_kb_s = downloaded / elapsed_time / 1024
                progress = (downloaded / total_length) * 100 if total_length else 0

                print(
                    f"Downloaded: {downloaded / (1024 * 1024):.2f} MB "
                    f"({progress:.2f}% complete) | Speed: {speed_kb_s:.2f} KB/s "
                    f"| Time elapsed: {elapsed_time:.2f} s"
                )

            print(f"Download complete! File saved as {filename}")


def ensure_subject(ix: Interface, proj: str, subj: str, auto: bool = True):
    if not auto:
        raise RuntimeError(f"Subject creation disabled but may be needed for {subj}")

    s_path = f"/data/projects/{proj}/subjects/{subj}"
    try:
        ix.put(s_path)
    except Exception:
        pass


def parse_ids(stem: str, cfg_project: str) -> Tuple[str, str, str]:
    """
    Expect filename:  <PROJECT>_<SUBJECT>_<SESSION>.<ext>
    where <PROJECT> == cfg['project']  (may contain underscores).
    """
    pref = f"{cfg_project}_"
    if not stem.startswith(pref):
        raise ValueError(f"{stem} doesn’t start with project '{cfg_project}_'")

    remainder = stem[len(pref) :]
    try:
        subject, session = remainder.rsplit("_", 1)
    except ValueError:
        raise ValueError("Need exactly one '_' after project for subject/session")

    return cfg_project, subject, session
