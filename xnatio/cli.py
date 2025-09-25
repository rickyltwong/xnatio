from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Optional

from .config import load_config
from .xnat_client import XNATClient
from .utils import is_allowed_archive, zip_dir_to_temp


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
        dest="env_file",
        type=Path,
        default=None,
        help="Path to .env file that overrides environment variables",
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
        dest="env_file",
        type=Path,
        default=None,
        help="Path to .env file that overrides environment variables",
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
        dest="env_file",
        type=Path,
        default=None,
        help="Path to .env file that overrides environment variables",
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
        dest="env_file",
        type=Path,
        default=None,
        help="Path to .env file that overrides environment variables",
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
        dest="env_file",
        type=Path,
        default=None,
        help="Path to .env file that overrides environment variables",
    )
    create_proj.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    delete_scans = subparsers.add_parser(
        "delete-scans",
        help="Delete scan files for a given project, subject, and session",
    )
    delete_scans.add_argument("project", help="Project ID")
    delete_scans.add_argument("subject", help="Subject ID")
    delete_scans.add_argument("session", help="Session/experiment ID")
    delete_scans.add_argument(
        "--scan",
        required=True,
        help="Scan IDs to delete: use '*' to delete all scans, or comma-separated list like '1,2,3,4,6' for specific scans",
    )
    delete_scans.add_argument(
        "--confirm",
        action="store_true",
        help="Skip confirmation prompt (required for deletion)",
    )
    delete_scans.add_argument(
        "--env",
        dest="env_file",
        type=Path,
        default=None,
        help="Path to .env file that overrides environment variables",
    )
    delete_scans.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    # New: list-scans
    list_scans = subparsers.add_parser(
        "list-scans",
        help="List scan IDs for a given project, subject, and session",
    )
    list_scans.add_argument("project", help="Project ID")
    list_scans.add_argument("subject", help="Subject ID")
    list_scans.add_argument("session", help="Session/experiment ID")
    list_scans.add_argument(
        "--env",
        dest="env_file",
        type=Path,
        default=None,
        help="Path to .env file that overrides environment variables",
    )
    list_scans.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    return parser


def run_cli(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARN,
        format="%(asctime)s %(levelname)s %(name)s ┊ %(message)s",
    )

    if args.command == "upload-dicom":
        cfg = load_config(args.env_file)
        client = XNATClient.from_config(cfg)

        inp: Path = args.input
        tmp_zip: Optional[Path] = None
        try:
            if inp.is_dir():
                logging.getLogger(__name__).info(f"Creating ZIP from directory {inp}…")
                tmp_zip = zip_dir_to_temp(inp)
                archive = tmp_zip
            elif inp.is_file():
                if not is_allowed_archive(inp):
                    parser.error(
                        "Unsupported archive type. Accepted: .zip, .tar, .tar.gz, .tgz (or pass a directory)"
                    )
                archive = inp
            else:
                parser.error(f"Input not found: {inp}")

            client.upload_dicom_zip(
                archive,
                project=args.project,
                subject=args.subject,
                session=args.session,
                import_handler="DICOM-zip",
                ignore_unparsable=True,
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
        cfg = load_config(args.env_file)
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
        cfg = load_config(args.env_file)
        client = XNATClient.from_config(cfg)
        client.extract_session_downloads(args.session_dir)
        return 0

    if args.command == "upload-resource":
        cfg = load_config(args.env_file)
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
        cfg = load_config(args.env_file)
        client = XNATClient.from_config(cfg)
        client.create_project(project_id=args.project_id, description=args.description)
        return 0

    if args.command == "delete-scans":
        cfg = load_config(args.env_file)
        client = XNATClient.from_config(cfg)

        # Parse scan IDs
        scan_ids_to_delete = args.scan
        if scan_ids_to_delete == "*":
            scan_ids = None  # Delete all scans
            scan_description = "ALL scans"
        else:
            scan_ids = [s.strip() for s in scan_ids_to_delete.split(",")]
            scan_description = f"scans {', '.join(scan_ids)}"

        if not args.confirm:
            print(f"WARNING: This will permanently delete {scan_description} for:")
            print(f"  Project: {args.project}")
            print(f"  Subject: {args.subject}")
            print(f"  Session: {args.session}")
            print()
            print("This action cannot be undone!")
            print()
            response = input("Type 'DELETE' to confirm, or anything else to cancel: ")
            if response != "DELETE":
                print("Operation cancelled.")
                return 1

        deleted_scans = client.delete_scans(
            project=args.project,
            subject=args.subject,
            session=args.session,
            scan_ids=scan_ids,
        )

        if deleted_scans:
            print(f"Deletion complete. Removed {len(deleted_scans)} scans.")
            print("Deleted scan IDs:", ", ".join(deleted_scans))
        else:
            print("No scans were deleted.")

        return 0

    if args.command == "list-scans":
        cfg = load_config(args.env_file)
        client = XNATClient.from_config(cfg)
        ids = client.list_scans(
            project=args.project, subject=args.subject, session=args.session
        )
        if ids:
            print("\n".join(ids))
        return 0

    # If we get here, command was not recognized
    parser.error(f"Unknown command: {args.command}")
    return 1
