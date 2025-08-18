import argparse
import logging
from pathlib import Path

from .config import load_config
from .xnat_client import XNATClient


_ALLOWED_EXTS = {".zip", ".tar", ".tgz"}


def _is_allowed_archive(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith(".tar.gz"):
        return True
    return path.suffix.lower() in _ALLOWED_EXTS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="xnatio", description="XNAT CLI utilities")

    subparsers = parser.add_subparsers(dest="command", required=True)

    upload = subparsers.add_parser(
        "upload-zip",
        help="Upload a ZIP/TAR archive to XNAT and push non-DICOM files to MISC",
    )
    upload.add_argument("archive", type=Path, help="Path to ZIP/TAR archive")
    upload.add_argument(
        "--env",
        dest="env_name",
        default=None,
        help="Select .env file: default uses .env, pass 'dev' to use .env.dev",
    )
    upload.add_argument(
        "--project", dest="project_override", default=None, help="Override project ID"
    )
    upload.add_argument(
        "--subject", dest="subject_override", default=None, help="Override subject ID"
    )
    upload.add_argument(
        "--session", dest="session_override", default=None, help="Override session/experiment ID"
    )
    upload.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    dl = subparsers.add_parser(
        "download-session",
        help="Download scans and resources for a session as ZIPs",
    )
    dl.add_argument("project", help="Project ID")
    dl.add_argument("subject", help="Subject ID")
    dl.add_argument("session", help="Session/experiment ID")
    dl.add_argument("output", type=Path, help="Output directory")
    dl.add_argument(
        "--env",
        dest="env_name",
        default=None,
        help="Select .env file: default uses .env, pass 'dev' to use .env.dev",
    )
    dl.add_argument(
        "--include-assessors",
        action="store_true",
        help="Also download assessor resources",
    )
    dl.add_argument(
        "--include-recons",
        action="store_true",
        help="Also download reconstruction resources",
    )
    dl.add_argument(
        "--unzip",
        action="store_true",
        help="Extract downloaded ZIPs into folders and remove the ZIP files",
    )
    dl.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    ex = subparsers.add_parser(
        "extract-session",
        help="Extract all zips in a session directory into scans/ and resources/<label>/",
    )
    ex.add_argument("session_dir", type=Path, help="Session directory containing downloaded ZIPs")
    ex.add_argument(
        "--env",
        dest="env_name",
        default=None,
        help="Select .env file: default uses .env, pass 'dev' to use .env.dev",
    )
    ex.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    return parser


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARN,
        format="%(asctime)s %(levelname)s %(name)s ┊ %(message)s",
    )

    if args.command == "upload-zip":
        archive: Path = args.archive
        if not archive.exists() or not archive.is_file():
            parser.error(f"Archive not found: {archive}")
        if not _is_allowed_archive(archive):
            parser.error(
                "Unsupported archive type. Accepted: .zip, .tar, .tar.gz, .tgz"
            )

        cfg = load_config(args.env_name)
        client = XNATClient.from_config(cfg)
        client.upload_archive(
            archive,
            project=args.project_override,
            subject=args.subject_override,
            session=args.session_override,
            auto_subject=bool(cfg.get("auto_subject", True)),
        )
        return 0

    if args.command == "download-session":
        cfg = load_config(args.env_name)
        client = XNATClient.from_config(cfg)
        out_dir: Path = args.output
        client.download_session(
            project=args.project,
            subject=args.subject,
            session=args.session,
            output_dir=out_dir,
            include_assessors=args.include_assessors,
            include_recons=args.include_recons,
        )
        if args.unzip:
            session_dir = out_dir / args.session
            client.extract_session_downloads(session_dir)
            # remove zip files after extraction
            for zip_path in session_dir.glob("*.zip"):
                try:
                    zip_path.unlink()
                except Exception:
                    logging.getLogger(__name__).warning(f"Failed to remove {zip_path}")
        return 0

    if args.command == "extract-session":
        cfg = load_config(args.env_name)
        client = XNATClient.from_config(cfg)
        client.extract_session_downloads(args.session_dir)
        return 0

    parser.error("Unknown command")
    return 2
