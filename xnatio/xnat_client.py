from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Optional, Tuple, Sequence
from urllib.parse import quote

import requests
from pyxnat import Interface
import zipfile
import tempfile
from xml.etree.ElementTree import Element, SubElement, tostring


class XNATClient:
    """High-level client for interacting with an XNAT server.

    This class wraps a `pyxnat.Interface` for authenticated API access and also
    maintains a `requests.Session` for direct HTTP endpoints not covered by
    `pyxnat` (e.g., import service, bulk zip downloads).

    Use `XNATClient.from_config` to construct from the project's .env config.
    """

    def __init__(
        self,
        server: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = True,
        http_timeouts: Tuple[int, int] = (60, 72000),
        logger: Optional[logging.Logger] = None,
    ):
        """Create a new XNAT client.

        Parameters
        - server: Base URL of the XNAT server (e.g., https://xnat.example.org)
        - username: XNAT username
        - password: XNAT password
        - verify_tls: Whether to verify TLS certificates
        - http_timeouts: (connect_timeout_seconds, read_timeout_seconds)
        - logger: Optional logger; if None, a module logger is used
        """
        self.server = server.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.http_timeouts = http_timeouts
        self.log = logger or logging.getLogger(__name__)

        # Authenticated XNAT interface
        self.interface: Interface = Interface(
            server=self.server, user=self.username, password=self.password
        )

        # Reusable HTTP session for endpoints not abstracted by pyxnat
        self.http = requests.Session()
        self.http.auth = (self.username, self.password)
        self.http.verify = self.verify_tls

    @classmethod
    def from_config(cls, cfg: Dict[str, object]) -> "XNATClient":
        """Construct a client from a dict loaded via .env.

        Expected keys in cfg: server, user, password.
        """
        return cls(
            server=str(cfg["server"]),
            username=str(cfg["user"]),
            password=str(cfg["password"]),
            verify_tls=bool(cfg.get("verify_tls", True)),
        )

    def create_project(
        self, project_id: str, description: Optional[str] = None
    ) -> None:
        """Create a new project using XNAT REST API.

        This sends an XML document to POST /data/projects with required
        fields ID, secondary_ID, and name set to the same provided value.
        Optionally sets description if provided.

        Treats HTTP 200/201 as success, and 409 (already exists) as a no-op success.
        """
        ns = "http://nrg.wustl.edu/xnat"
        root = Element(f"{{{ns}}}projectData")
        SubElement(root, f"{{{ns}}}ID").text = project_id
        SubElement(root, f"{{{ns}}}secondary_ID").text = project_id
        SubElement(root, f"{{{ns}}}name").text = project_id
        if description:
            SubElement(root, f"{{{ns}}}description").text = description

        xml_body = tostring(root, encoding="utf-8", xml_declaration=True)
        url = f"{self.server}/data/projects"
        r = self.http.post(
            url,
            data=xml_body,
            headers={"Content-Type": "application/xml"},
            timeout=self.http_timeouts,
        )
        if r.status_code in (200, 201):
            self.log.info(f"Project create OK ({r.status_code})")
            return
        if r.status_code == 409:
            self.log.info("Project already exists (409)")
            return
        r.raise_for_status()

    def ensure_subject(
        self, project: str, subject: str, *, auto_create: bool = True
    ) -> None:
        """Ensure a subject exists in the given project.

        If `auto_create` is True, attempt to create the subject (no-op if it exists).
        Raises RuntimeError if creation is disabled and subject may be missing.
        """
        if not auto_create:
            raise RuntimeError(
                f"Subject creation disabled but may be needed for {subject}"
            )

        subject_path = f"/data/projects/{project}/subjects/{subject}"
        try:
            self.interface.put(subject_path)
        except Exception:
            # Best-effort; subject may already exist.
            pass

    def ensure_session(self, project: str, subject: str, session: str) -> None:
        """Ensure a session exists for the subject in the project.

        Best-effort creation; no error if it already exists.
        """
        session_path = (
            f"/data/projects/{project}/subjects/{subject}/experiments/{session}"
        )
        try:
            # Create MR session by default; XNAT will upsert if existing
            self.interface.put(session_path, params={"xsiType": "xnat:mrSessionData"})
        except Exception:
            pass

    def upload_dicom_zip(
        self,
        archive: Path,
        *,
        project: str,
        subject: str,
        session: str,
        import_handler: str = "DICOM-zip",
        ignore_unparsable: bool = True,
        dest: Optional[str] = None,
        overwrite: str = "delete",
        overwrite_files: bool = True,
        quarantine: bool = False,
        trigger_pipelines: bool = True,
        rename: bool = False,
        srcs: Optional[Sequence[str]] = None,
        http_session_listener: Optional[str] = None,
        direct_archive: bool = True,
    ) -> None:
        """Upload a DICOM ZIP/TAR archive to the XNAT import service.

        Ensures the subject and session exist, then POSTs the archive to
        `/data/services/import` with the given handler.

        Parameters
        - project, subject, session: Target identifiers (used unless `dest` routes explicitly)
        - import_handler: XNAT import handler (default "DICOM-zip")
        - ignore_unparsable: If True, discard non-DICOM files in archive (XNAT 1.8.3+)
        - dest: Optional destination route (e.g., "/prearchive" or "/prearchive/projects/PROJECT")
        - overwrite: "none" | "append" | "delete" (default "none")
        - overwrite_files: Allow file overwrites for merges (default False)
        - quarantine: Place modified content in quarantine (default False → follow project settings)
        - trigger_pipelines: Run AutoRun pipeline for affected sessions (default True)
        - rename: With gradual-DICOM, instruct XNAT to rename incoming DICOM files (default False)
        - srcs: Alternate mode for server-side sources (comma-joined if provided). Typically unused when uploading a file body.
        - http_session_listener: Optional identifier used by the web-based uploader for tracking
        - direct_archive: Use direct-to-archive behavior (XNAT 1.8.3+, default False)
        """
        log = logging.getLogger(archive.name)
        self.ensure_subject(project, subject, auto_create=True)
        # self.ensure_session(project, subject, session)

        imp_url = f"{self.server}/data/services/import"
        log.info(
            f"Starting upload of {archive.name} ({archive.stat().st_size / (1024 * 1024 * 1024):.1f} GB); direct-archive option: {direct_archive}"
        )

        # All parameters go on the query string according to XNAT API documentation
        params = {
            "import-handler": import_handler,
            "Ignore-Unparsable": "true" if ignore_unparsable else "false",
            # Common targeting fields supported by DICOM-zip when not using `dest`
            "project": project,
            "subject": subject,
            "session": session,
            # Explicit defaults mirroring server behavior
            "overwrite": overwrite,
            "overwrite_files": "true" if overwrite_files else "false",
            "quarantine": "true" if quarantine else "false",
            "triggerPipelines": "true" if trigger_pipelines else "false",
            "rename": "true" if rename else "false",
            # direct-archive option
            "Direct-Archive": "true" if direct_archive else "false",
        }

        if dest:
            params["dest"] = dest
        if http_session_listener:
            params["http-session-listener"] = http_session_listener
        if srcs:
            # API allows multiple src attributes or comma-separated list
            params["src"] = ",".join(srcs)

        # Use multipart form upload with generic 'file' field name; data-binary doesn't work after testing
        with open(archive, "rb") as f:
            files = {"file": (archive.name, f)}

            resp = self.http.post(
                imp_url,
                params=params,
                files=files,  # multipart form data
                timeout=self.http_timeouts,
                stream=True,
            )
            resp.raise_for_status()
            log.info(f"DICOM import OK ({resp.status_code})")

    def upload_session_resource_dir(
        self,
        *,
        project: str,
        subject: str,
        session: str,
        resource_label: str,
        local_dir: Path,
    ) -> None:
        """Upload all files under a local directory to a session resource.

        Files are uploaded preserving their relative paths under ``local_dir`` to
        ``/resources/<resource_label>/files/<relative_path>`` on the session.
        Subject and session are ensured to exist prior to upload.
        """
        if not local_dir.exists() or not local_dir.is_dir():
            raise ValueError(f"Directory not found: {local_dir}")

        self.ensure_subject(project, subject, auto_create=True)
        self.ensure_session(project, subject, session)

        log = logging.getLogger(f"{session}:{resource_label}")
        log.info(f"Uploading directory {local_dir} → resource {resource_label}")
        base = f"{self.server}/data/projects/{project}/subjects/{subject}/experiments/{session}"
        uploaded = 0
        failed = 0
        for path in sorted(local_dir.rglob("*")):
            if not path.is_file():
                continue
            rel_path = path.relative_to(local_dir).as_posix()
            url = f"{base}/resources/{quote(resource_label)}/files/{quote(rel_path)}?inbody=true"
            try:
                with open(path, "rb") as f:
                    r = self.http.put(
                        url,
                        data=f,
                        headers={"Content-Type": "application/octet-stream"},
                        timeout=self.http_timeouts,
                        stream=True,
                    )
                if r.status_code in (200, 201):
                    uploaded += 1
                    if log.isEnabledFor(logging.INFO):
                        log.info(f"OK {rel_path}")
                else:
                    failed += 1
                    log.warning(f"{rel_path} → {r.status_code}")
            except Exception as e:
                failed += 1
                log.warning(f"{rel_path} → error: {e}")
        log.info(f"Upload complete: {uploaded} ok, {failed} failed")

    def upload_session_resource_zip_dir(
        self,
        *,
        project: str,
        subject: str,
        session: str,
        resource_label: str,
        local_dir: Path,
        zip_name: Optional[str] = None,
    ) -> None:
        """Zip a directory and upload it once to a session resource with extract=true.

        The directory is archived locally into a temporary ZIP, preserving relative paths,
        then PUT as a single request to the resource endpoint with `?extract=true&inbody=true`.
        """
        if not local_dir.exists() or not local_dir.is_dir():
            raise ValueError(f"Directory not found: {local_dir}")

        self.ensure_subject(project, subject, auto_create=True)
        self.ensure_session(project, subject, session)

        base = f"{self.server}/data/projects/{project}/subjects/{subject}/experiments/{session}"
        zip_name = zip_name or f"{resource_label}.zip"
        url = (
            f"{base}/resources/{quote(resource_label)}/files/{quote(zip_name)}"
            f"?extract=true&inbody=true"
        )

        log = logging.getLogger(f"{session}:{resource_label}")
        log.info(f"Creating ZIP from {local_dir} → {zip_name}")
        tmp_dir = Path(tempfile.gettempdir())
        tmp_zip = tmp_dir / f"xnatio_{zip_name}"
        # Create zip
        with zipfile.ZipFile(
            tmp_zip, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
        ) as zf:
            for path in sorted(local_dir.rglob("*")):
                if not path.is_file():
                    continue
                rel = path.relative_to(local_dir).as_posix()
                zf.write(path, arcname=rel)
        size_mb = tmp_zip.stat().st_size / (1024 * 1024)
        log.info(f"ZIP ready ({size_mb:.1f} MB). Uploading once with extract=true...")

        try:
            with open(tmp_zip, "rb") as f:
                r = self.http.put(
                    url,
                    data=f,
                    headers={"Content-Type": "application/zip"},
                    timeout=self.http_timeouts,
                    stream=True,
                )
            r.raise_for_status()
            log.info(f"Extract upload OK ({r.status_code})")
        finally:
            try:
                tmp_zip.unlink()
            except Exception:
                pass

    def _download_stream(self, url: str, out_path: Path) -> None:
        """Stream a URL to a local file using the client's HTTP session.

        Logs cumulative bytes downloaded periodically and on completion when INFO logging is enabled.
        """
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with self.http.get(url, stream=True, timeout=(30, 7200)) as r:
            r.raise_for_status()
            with open(out_path, "wb") as f:
                total = 0
                report_threshold = 5 * 1024 * 1024  # 5 MB
                next_report = report_threshold
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    f.write(chunk)
                    total += len(chunk)
                    if total >= next_report and self.log.isEnabledFor(logging.INFO):
                        self.log.info(f"{out_path.name}: downloaded {total:,} bytes")
                        next_report += report_threshold
                if self.log.isEnabledFor(logging.INFO):
                    self.log.info(
                        f"{out_path.name}: download complete ({total:,} bytes)"
                    )

    def download_scans_zip(
        self, project: str, subject: str, session: str, out_dir: Path
    ) -> Path:
        """Download all scan files for a session as a single ZIP (scans.zip)."""
        base = f"{self.server}/data/projects/{project}/subjects/{subject}/experiments/{session}"
        out = out_dir / "scans.zip"
        self._download_stream(f"{base}/scans/ALL/files?format=zip", out)
        return out

    def download_session_resources_zip(
        self, project: str, subject: str, session: str, out_dir: Path
    ) -> Path:
        """Download all session-level resources as separate ZIP files.

        This enumerates resource labels via the JSON listing endpoint and
        downloads each resource individually as:
          session_resources_<label>.zip
        Returns the directory path containing the downloaded zips.
        """
        base = f"{self.server}/data/projects/{project}/subjects/{subject}/experiments/{session}"
        # 1) list resources
        list_url = f"{base}/resources?format=json"
        resp = self.http.get(list_url, timeout=(30, 120))
        resp.raise_for_status()
        data = resp.json()
        results = (data or {}).get("ResultSet", {}).get("Result", [])
        labels = [r.get("label") for r in results if r.get("label")]
        # 2) download each resource
        for label in labels:
            label_q = quote(label)
            filename_safe = label.replace("/", "_").replace(" ", "_")
            out = out_dir / f"resources_{filename_safe}.zip"
            self._download_stream(f"{base}/resources/{label_q}/files?format=zip", out)
        return out_dir

    def download_assessor_or_recon_resources_zip(
        self,
        project: str,
        subject: str,
        session: str,
        out_dir: Path,
        *,
        kind: str,
    ) -> Optional[Path]:
        """Download assessor or reconstruction resources (ALL) as a ZIP.

        Parameters
        - kind: "assessors" or "reconstructions"
        Returns the output Path if downloaded, else None.
        """
        if kind not in {"assessors", "reconstructions"}:
            raise ValueError("kind must be 'assessors' or 'reconstructions'")
        base = f"{self.server}/data/projects/{project}/subjects/{subject}/experiments/{session}"
        name = (
            "assessor_resources.zip" if kind == "assessors" else "recon_resources.zip"
        )
        out = out_dir / name
        self._download_stream(f"{base}/{kind}/ALL/resources/ALL/files?format=zip", out)
        return out

    def download_session(
        self,
        project: str,
        subject: str,
        session: str,
        output_dir: Path,
        *,
        include_assessors: bool = False,
        include_recons: bool = False,
        parallel: bool = True,
        max_workers: int = 4,
    ) -> None:
        """Download scans and resources for a session into `output_dir`.

        This orchestrates modular downloads and can optionally run them in parallel:
        - scans.zip
        - session_resources.zip
        - assessor_resources.zip (optional)
        - recon_resources.zip (optional)
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create a subdirectory named after the session label
        session_dir = output_dir / session
        session_dir.mkdir(parents=True, exist_ok=True)

        tasks = [
            (lambda: self.download_scans_zip(project, subject, session, session_dir)),
            (
                lambda: self.download_session_resources_zip(
                    project, subject, session, session_dir
                )
            ),
        ]
        if include_assessors:
            tasks.append(
                lambda: self.download_assessor_or_recon_resources_zip(
                    project, subject, session, session_dir, kind="assessors"
                )
            )
        if include_recons:
            tasks.append(
                lambda: self.download_assessor_or_recon_resources_zip(
                    project, subject, session, session_dir, kind="reconstructions"
                )
            )

        if parallel and len(tasks) > 1:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(tasks))) as ex:
                list(ex.map(lambda fn: fn(), tasks))
        else:
            for fn in tasks:
                fn()

    def extract_session_downloads(self, session_dir: Path) -> None:
        """Extract all zips produced by download_session into folders.

        Layout after extraction:
        - scans.zip → scans/
        - resources_<label>.zip → resources/<label>/
        - assessor_resources.zip → assessors/
        - recon_resources.zip → reconstructions/
        Unknown zip names are extracted to a folder named after the zip stem.
        """
        if not session_dir.exists() or not session_dir.is_dir():
            raise ValueError(f"Session directory not found: {session_dir}")

        for zip_path in sorted(session_dir.glob("*.zip")):
            name = zip_path.name
            if name == "scans.zip":
                target_dir = session_dir / "scans"
            elif name.startswith("resources_") and name.endswith(".zip"):
                label = name[len("resources_") : -len(".zip")]
                target_dir = session_dir / "resources" / label
            elif name == "assessor_resources.zip":
                target_dir = session_dir / "assessors"
            elif name == "recon_resources.zip":
                target_dir = session_dir / "reconstructions"
            else:
                target_dir = session_dir / zip_path.stem

            target_dir.mkdir(parents=True, exist_ok=True)
            self.log.info(f"Extracting {name} → {target_dir}")
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(target_dir)
            self.log.info(f"Extracted {name}")

    def upload_session_resource_file(
        self,
        *,
        project: str,
        subject: str,
        session: str,
        resource_label: str,
        file_path: Path,
        remote_name: Optional[str] = None,
    ) -> None:
        """Upload a single file to a session resource using one PUT with inbody=true.

        If ``remote_name`` is not provided, the local filename is used.
        """
        if not file_path.exists() or not file_path.is_file():
            raise ValueError(f"File not found: {file_path}")

        self.ensure_subject(project, subject, auto_create=True)
        self.ensure_session(project, subject, session)

        base = f"{self.server}/data/projects/{project}/subjects/{subject}/experiments/{session}"
        remote = quote(remote_name or file_path.name)
        url = f"{base}/resources/{quote(resource_label)}/files/{remote}?inbody=true"
        log = logging.getLogger(f"{session}:{resource_label}")
        size_mb = file_path.stat().st_size / (1024 * 1024)
        log.info(
            f"Uploading file {file_path} ({size_mb:.1f} MB) → {resource_label}/{remote}"
        )
        with open(file_path, "rb") as f:
            r = self.http.put(
                url,
                data=f,
                headers={"Content-Type": "application/octet-stream"},
                timeout=self.http_timeouts,
                stream=True,
            )
        r.raise_for_status()
        log.info(f"File upload OK ({r.status_code})")

    def delete_scans(
        self,
        project: str,
        subject: str,
        session: str,
        scan_ids: Optional[list[str]] = None,
    ) -> list[str]:
        """
        Delete scan files for a given project, subject, and session.

        Parameters:
        - project: Project ID
        - subject: Subject ID
        - session: Session/experiment ID
        - scan_ids: List of specific scan IDs to delete, or None to delete all scans

        Returns:
        - List of scan IDs that were successfully deleted
        """
        if scan_ids is None:
            self.log.info(f"Deleting ALL scans for {project}/{subject}/{session}")
        else:
            self.log.info(
                f"Deleting scans {', '.join(scan_ids)} for {project}/{subject}/{session}"
            )

        # First, get list of available scans for this session
        session_path = (
            f"/data/projects/{project}/subjects/{subject}/experiments/{session}"
        )
        scans_url = f"{session_path}/scans?format=json"

        try:
            resp = self.http.get(f"{self.server}{scans_url}", timeout=(30, 120))
            resp.raise_for_status()
            data = resp.json()

            # Extract available scan IDs from the response
            results = (data or {}).get("ResultSet", {}).get("Result", [])
            available_scan_ids = [r.get("ID") for r in results if r.get("ID")]

            if not available_scan_ids:
                self.log.info(f"No scans found for {project}/{subject}/{session}")
                return []

            self.log.info(f"Available scans: {', '.join(available_scan_ids)}")

            # Determine which scans to delete
            if scan_ids is None:
                # Delete all scans
                scans_to_delete = available_scan_ids
            else:
                # Delete only specified scans that exist
                scans_to_delete = []
                for scan_id in scan_ids:
                    if scan_id in available_scan_ids:
                        scans_to_delete.append(scan_id)
                    else:
                        self.log.warning(f"Scan {scan_id} not found, skipping")

                if not scans_to_delete:
                    self.log.info("No valid scan IDs to delete")
                    return []

            self.log.info(
                f"Will delete {len(scans_to_delete)} scans: {', '.join(scans_to_delete)}"
            )

            # Delete each scan using HTTP session (respects SSL settings)
            deleted_scans = []
            for scan_id in scans_to_delete:
                try:
                    scan_url = f"{self.server}{session_path}/scans/{scan_id}"
                    self.log.info(f"Deleting scan {scan_id}...")

                    # Use HTTP session DELETE request (respects verify_tls setting)
                    resp = self.http.delete(scan_url, timeout=(30, 120))
                    resp.raise_for_status()
                    deleted_scans.append(scan_id)
                    self.log.info(f"✓ Deleted scan {scan_id}")

                except Exception as e:
                    self.log.error(f"✗ Failed to delete scan {scan_id}: {e}")
                    continue

            self.log.info(
                f"Successfully deleted {len(deleted_scans)} out of {len(scans_to_delete)} scans"
            )
            return deleted_scans

        except Exception as e:
            self.log.error(
                f"Failed to list/delete scans for {project}/{subject}/{session}: {e}"
            )
            raise
