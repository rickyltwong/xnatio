"""Tests for xnatio.cli module."""

from __future__ import annotations

import argparse

import pytest

from xnatio.cli import build_parser


class TestBuildParser:
    """Tests for build_parser function."""

    @pytest.fixture
    def parser(self) -> argparse.ArgumentParser:
        """Create parser fixture."""
        return build_parser()

    def test_parser_has_subcommands(self, parser: argparse.ArgumentParser) -> None:
        """Test that all expected subcommands are present."""
        # Parse with --help would exit, so we check _subparsers
        subparsers_actions = [
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        assert len(subparsers_actions) == 1

        choices = subparsers_actions[0].choices
        expected_commands = [
            "upload-dicom",
            "download-session",
            "extract-session",
            "upload-resource",
            "create-project",
            "delete-scans",
            "list-scans",
            "refresh-catalogs",
        ]
        for cmd in expected_commands:
            assert cmd in choices, f"Missing subcommand: {cmd}"

    def test_upload_dicom_args(self, parser: argparse.ArgumentParser) -> None:
        """Test upload-dicom command arguments."""
        args = parser.parse_args(
            ["upload-dicom", "PROJ", "SUBJ", "SESS", "/path/to/archive.zip"]
        )
        assert args.command == "upload-dicom"
        assert args.project == "PROJ"
        assert args.subject == "SUBJ"
        assert args.session == "SESS"
        assert str(args.input) == "/path/to/archive.zip"
        assert args.verbose is False

    def test_upload_dicom_verbose(self, parser: argparse.ArgumentParser) -> None:
        """Test upload-dicom verbose flag."""
        args = parser.parse_args(
            ["upload-dicom", "-v", "PROJ", "SUBJ", "SESS", "/path/to/archive.zip"]
        )
        assert args.verbose is True

    def test_download_session_args(self, parser: argparse.ArgumentParser) -> None:
        """Test download-session command arguments."""
        args = parser.parse_args(
            ["download-session", "PROJ", "SUBJ", "SESS", "/output/dir"]
        )
        assert args.command == "download-session"
        assert args.include_assessors is False
        assert args.include_recons is False
        assert args.unzip is False

    def test_download_session_optional_flags(
        self, parser: argparse.ArgumentParser
    ) -> None:
        """Test download-session optional flags."""
        args = parser.parse_args(
            [
                "download-session",
                "--include-assessors",
                "--include-recons",
                "--unzip",
                "PROJ",
                "SUBJ",
                "SESS",
                "/output/dir",
            ]
        )
        assert args.include_assessors is True
        assert args.include_recons is True
        assert args.unzip is True

    def test_delete_scans_args(self, parser: argparse.ArgumentParser) -> None:
        """Test delete-scans command arguments."""
        args = parser.parse_args(
            ["delete-scans", "PROJ", "SUBJ", "SESS", "--scan", "1,2,3"]
        )
        assert args.command == "delete-scans"
        assert args.scan == "1,2,3"
        assert args.confirm is False
        assert args.parallel is False
        assert args.max_workers == 4

    def test_delete_scans_all(self, parser: argparse.ArgumentParser) -> None:
        """Test delete-scans with wildcard."""
        args = parser.parse_args(
            ["delete-scans", "PROJ", "SUBJ", "SESS", "--scan", "*", "--confirm"]
        )
        assert args.scan == "*"
        assert args.confirm is True

    def test_delete_scans_parallel(self, parser: argparse.ArgumentParser) -> None:
        """Test delete-scans parallel options."""
        args = parser.parse_args(
            [
                "delete-scans",
                "PROJ",
                "SUBJ",
                "SESS",
                "--scan",
                "1,2,3",
                "--parallel",
                "--max-workers",
                "8",
            ]
        )
        assert args.parallel is True
        assert args.max_workers == 8

    def test_list_scans_args(self, parser: argparse.ArgumentParser) -> None:
        """Test list-scans command arguments."""
        args = parser.parse_args(["list-scans", "PROJ", "SUBJ", "SESS"])
        assert args.command == "list-scans"
        assert args.format == "text"

    def test_list_scans_json_format(self, parser: argparse.ArgumentParser) -> None:
        """Test list-scans with JSON format."""
        args = parser.parse_args(
            ["list-scans", "PROJ", "SUBJ", "SESS", "--format", "json"]
        )
        assert args.format == "json"

    def test_refresh_catalogs_args(self, parser: argparse.ArgumentParser) -> None:
        """Test refresh-catalogs command arguments."""
        args = parser.parse_args(["refresh-catalogs", "PROJ"])
        assert args.command == "refresh-catalogs"
        assert args.project == "PROJ"
        assert args.option is None
        assert args.parallel is False
        assert args.format == "text"

    def test_refresh_catalogs_options(self, parser: argparse.ArgumentParser) -> None:
        """Test refresh-catalogs with multiple options."""
        args = parser.parse_args(
            [
                "refresh-catalogs",
                "PROJ",
                "--option",
                "checksum",
                "--option",
                "delete",
                "--parallel",
                "--max-workers",
                "8",
                "--format",
                "json",
            ]
        )
        assert args.option == ["checksum", "delete"]
        assert args.parallel is True
        assert args.max_workers == 8
        assert args.format == "json"

    def test_create_project_args(self, parser: argparse.ArgumentParser) -> None:
        """Test create-project command arguments."""
        args = parser.parse_args(
            ["create-project", "NEW_PROJ", "--description", "Test project"]
        )
        assert args.command == "create-project"
        assert args.project_id == "NEW_PROJ"
        assert args.description == "Test project"

    def test_env_file_arg(self, parser: argparse.ArgumentParser) -> None:
        """Test --env argument is parsed correctly."""
        args = parser.parse_args(
            ["list-scans", "PROJ", "SUBJ", "SESS", "--env", "/path/to/.env"]
        )
        assert str(args.env_file) == "/path/to/.env"

    def test_missing_required_args_raises(
        self, parser: argparse.ArgumentParser
    ) -> None:
        """Test that missing required arguments raise error."""
        with pytest.raises(SystemExit):
            parser.parse_args(["upload-dicom"])  # Missing required args

        with pytest.raises(SystemExit):
            parser.parse_args(["delete-scans", "PROJ", "SUBJ", "SESS"])  # Missing --scan
