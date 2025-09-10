import zipfile
import tempfile
import uuid
from pathlib import Path


# Archive format constants and utilities
_ALLOWED_ARCHIVE_EXTS = {".zip", ".tar", ".tgz"}


def is_allowed_archive(path: Path) -> bool:
    """Check if a file path represents a supported archive format."""
    name = path.name.lower()
    if name.endswith(".tar.gz"):
        return True
    return path.suffix.lower() in _ALLOWED_ARCHIVE_EXTS


def zip_dir_to_temp(dir_path: Path) -> Path:
    """Create a temporary ZIP from a directory and return its path."""
    tmp_zip = (
        Path(tempfile.gettempdir()) / f"xnatio_{dir_path.name}_{uuid.uuid4().hex}.zip"
    )
    with zipfile.ZipFile(
        tmp_zip, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
    ) as zf:
        for path in sorted(dir_path.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(dir_path).as_posix()
            zf.write(path, arcname=rel)
    return tmp_zip


__all__ = [
    "is_allowed_archive",
    "zip_dir_to_temp",
]
