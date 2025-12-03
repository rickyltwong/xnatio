"""Tests for xnatio.utils module."""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

import pytest

from xnatio.utils import is_allowed_archive, zip_dir_to_temp


class TestIsAllowedArchive:
    """Tests for is_allowed_archive function."""

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("archive.zip", True),
            ("ARCHIVE.ZIP", True),
            ("archive.tar", True),
            ("archive.TAR", True),
            ("archive.tgz", True),
            ("archive.TGZ", True),
            ("archive.tar.gz", True),
            ("archive.TAR.GZ", True),
            ("image.png", False),
            ("document.pdf", False),
            ("archive.rar", False),
            ("archive.7z", False),
            ("file.txt", False),
            ("noextension", False),
        ],
    )
    def test_archive_detection(self, filename: str, expected: bool) -> None:
        """Test that archive formats are correctly detected."""
        path = Path(f"/some/path/{filename}")
        assert is_allowed_archive(path) == expected

    def test_tar_gz_with_double_extension(self) -> None:
        """Test that .tar.gz files are correctly detected."""
        assert is_allowed_archive(Path("/path/to/archive.tar.gz")) is True
        assert is_allowed_archive(Path("/path/to/archive.TAR.GZ")) is True


class TestZipDirToTemp:
    """Tests for zip_dir_to_temp function."""

    def test_creates_valid_zip(self) -> None:
        """Test that a valid ZIP file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test directory structure
            test_dir = Path(tmpdir) / "test_data"
            test_dir.mkdir()
            (test_dir / "file1.txt").write_text("content1")
            (test_dir / "subdir").mkdir()
            (test_dir / "subdir" / "file2.txt").write_text("content2")

            # Create zip
            zip_path = zip_dir_to_temp(test_dir)

            try:
                # Verify it's a valid zip
                assert zip_path.exists()
                assert zip_path.suffix == ".zip"
                assert zipfile.is_zipfile(zip_path)

                # Verify contents
                with zipfile.ZipFile(zip_path) as zf:
                    names = zf.namelist()
                    assert "file1.txt" in names
                    assert "subdir/file2.txt" in names
                    assert zf.read("file1.txt").decode() == "content1"
                    assert zf.read("subdir/file2.txt").decode() == "content2"
            finally:
                zip_path.unlink(missing_ok=True)

    def test_preserves_relative_paths(self) -> None:
        """Test that relative paths are preserved in the ZIP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "data"
            test_dir.mkdir()
            (test_dir / "level1").mkdir()
            (test_dir / "level1" / "level2").mkdir()
            (test_dir / "level1" / "level2" / "deep.txt").write_text("deep content")

            zip_path = zip_dir_to_temp(test_dir)

            try:
                with zipfile.ZipFile(zip_path) as zf:
                    assert "level1/level2/deep.txt" in zf.namelist()
            finally:
                zip_path.unlink(missing_ok=True)

    def test_unique_filename_per_call(self) -> None:
        """Test that each call creates a unique filename."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "data"
            test_dir.mkdir()
            (test_dir / "file.txt").write_text("test")

            zip1 = zip_dir_to_temp(test_dir)
            zip2 = zip_dir_to_temp(test_dir)

            try:
                assert zip1 != zip2
                assert zip1.name != zip2.name
            finally:
                zip1.unlink(missing_ok=True)
                zip2.unlink(missing_ok=True)

    def test_empty_directory(self) -> None:
        """Test handling of empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "empty"
            test_dir.mkdir()

            zip_path = zip_dir_to_temp(test_dir)

            try:
                assert zip_path.exists()
                with zipfile.ZipFile(zip_path) as zf:
                    assert len(zf.namelist()) == 0
            finally:
                zip_path.unlink(missing_ok=True)

    def test_skips_directories_in_listing(self) -> None:
        """Test that only files are added to the ZIP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "data"
            test_dir.mkdir()
            (test_dir / "empty_subdir").mkdir()
            (test_dir / "file.txt").write_text("content")

            zip_path = zip_dir_to_temp(test_dir)

            try:
                with zipfile.ZipFile(zip_path) as zf:
                    # Directory entries should not be in the zip
                    names = zf.namelist()
                    assert "file.txt" in names
                    # empty_subdir should not appear as it's empty
                    assert all("empty_subdir" not in n for n in names)
            finally:
                zip_path.unlink(missing_ok=True)
