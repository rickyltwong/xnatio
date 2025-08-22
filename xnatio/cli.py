import argparse
import logging
from pathlib import Path
import tempfile
import zipfile
import uuid

from .config import load_config
from .xnat_client import XNATClient


_ALLOWED_EXTS = {".zip", ".tar", ".tgz"}


def _is_allowed_archive(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith(".tar.gz"):
        return True
    return path.suffix.lower() in _ALLOWED_EXTS


def _zip_dir_to_temp(dir_path: Path) -> Path:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="xnatio", description="XNAT CLI utilities")

    subparsers = parser.add_subparsers(dest="command", required=True)

    upload = subparsers.add_parser(
        "upload-dicom",
        help="Upload a DICOM session from a ZIP/TAR archive or directory via import service",
    )
    upload.add_argument("project", help="Project ID")
    upload.add_argument("subject", help="Subject ID")
    upload.add_argument("session", help="Session/experiment ID")
    upload.add_argument(
        "input",
        type=Path,
        help="Path to ZIP/TAR(.gz)/TGZ archive or a directory of DICOM files",
    )
    upload.add_argument(
        "--env",
        dest="env_name",
        default=None,
        help="Select .env file: default uses .env, pass 'dev' to use .env.dev",
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
    dl.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    ex = subparsers.add_parser(
        "extract-session",
        help="Extract all zips in a session directory into scans/ and resources/<label>/",
    )
    ex.add_argument(
        "session_dir", type=Path, help="Session directory containing downloaded ZIPs"
    )
    ex.add_argument(
        "--env",
        dest="env_name",
        default=None,
        help="Select .env file: default uses .env, pass 'dev' to use .env.dev",
    )
    ex.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    upres = subparsers.add_parser(
        "upload-resource",
        help="Upload a file or directory to a session resource (dir is zipped and extracted server-side)",
    )
    upres.add_argument("project", help="Project ID")
    upres.add_argument("subject", help="Subject ID")
    upres.add_argument("session", help="Session/experiment ID")
    upres.add_argument("resource", help="Resource label (e.g., BIDS)")
    upres.add_argument("path", type=Path, help="Local file or directory to upload")
    upres.add_argument(
        "--zip-name",
        default=None,
        help="Optional zip filename to use on server (defaults to <resource>.zip)",
    )
    upres.add_argument(
        "--env",
        dest="env_name",
        default=None,
        help="Select .env file: default uses .env, pass 'dev' to use .env.dev",
    )
    upres.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    # New: create-project
    create_proj = subparsers.add_parser(
        "create-project",
        help="Create a new XNAT project via REST API",
    )
    create_proj.add_argument(
        "project_id", help="Project ID (used for ID, secondary_ID, and name)"
    )
    create_proj.add_argument(
        "--description",
        default=None,
        help="Optional project description",
    )
    create_proj.add_argument(
        "--env",
        dest="env_name",
        default=None,
        help="Select .env file: default uses .env, pass 'dev' to use .env.dev",
    )
    create_proj.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    return parser


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARN,
        format="%(asctime)s %(levelname)s %(name)s ┊ %(message)s",
    )

    if args.command == "upload-dicom":
        cfg = load_config(args.env_name)
        client = XNATClient.from_config(cfg)

        inp: Path = args.input
        tmp_zip: Path | None = None
        try:
            if inp.is_dir():
                logging.getLogger(__name__).info(f"Creating ZIP from directory {inp}…")
                tmp_zip = _zip_dir_to_temp(inp)
                archive = tmp_zip
            elif inp.is_file():
                if not _is_allowed_archive(inp):
                    parser.error(
                        "Unsupported archive type. Accepted: .zip, .tar, .tar.gz, .tgz (or pass a directory)"
                    )
                archive = inp
            else:
                parser.error(f"Input not found: {inp}")

            client.upload_archive(
                archive,
                project=args.project,
                subject=args.subject,
                session=args.session,
            )
        finally:
            if tmp_zip is not None:
                try:
                    tmp_zip.unlink()
                except Exception:
                    logging.getLogger(__name__).warning(
                        f"Failed to remove temp zip {tmp_zip}"
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

    if args.command == "upload-resource":
        cfg = load_config(args.env_name)
        client = XNATClient.from_config(cfg)
        p: Path = args.path
        if p.is_dir():
            client.upload_session_resource_zip_dir(
                project=args.project,
                subject=args.subject,
                session=args.session,
                resource_label=args.resource,
                local_dir=p,
                zip_name=args.zip_name,
            )
        else:
            client.upload_session_resource_file(
                project=args.project,
                subject=args.subject,
                session=args.session,
                resource_label=args.resource,
                file_path=p,
            )
        return 0

    if args.command == "create-project":
        cfg = load_config(args.env_name)
        client = XNATClient.from_config(cfg)
        client.create_project(project_id=args.project_id, description=args.description)
        logging.getLogger(__name__).info(
            f"Project '{args.project_id}' created or already exists."
        )
        return 0

    parser.error("Unknown command")
    return 2
