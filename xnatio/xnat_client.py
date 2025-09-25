from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Optional, Tuple, Sequence
from urllib.parse import quote
from pyxnat import Interface
import zipfile
import tempfile


class XNATClient:
    """High-level client for interacting with an XNAT server.

    This class wraps a `pyxnat.Interface` for authenticated API access. It uses
    the object API for metadata CRUD and the Interface HTTP wrappers for endpoints
    and streaming operations (e.g., import service, bulk zip downloads).

    Use `XNATClient.from_config` to construct from the project's .env config.
    """

    def __init__(
        self,
        server: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = True,
        http_timeouts: Tuple[int, int] = (120, 604800),
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
            server=self.server,
            user=self.username,
            password=self.password,
            verify=self.verify_tls,
        )

        # All HTTP requests go through the pyxnat Interface wrappers

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
        """Create a new project using pyxnat object API if missing; set description."""
        project = self.interface.select.project(project_id)
        if not project.exists():
            project.insert()
            self.log.info(f"Project created: {project_id}")
        if description:
            try:
                project.attrs.set("xnat:projectData/description", description)
            except Exception:
                # Some XNAT versions restrict description updates; ignore errors silently
                pass

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

        subj = self.interface.select.project(project).subject(subject)
        try:
            if not subj.exists():
                subj.insert()
        except Exception:
            pass

    def ensure_session(self, project: str, subject: str, session: str) -> None:
        """Ensure a session exists for the subject in the project.

        Best-effort creation; no error if it already exists.
        """
        sess = (
            self.interface.select.project(project).subject(subject).experiment(session)
        )
        try:
            if not sess.exists():
                # Create MR session by default
                sess.insert(experiments="xnat:mrSessionData")
        except Exception:
            pass

    def test_connection(self) -> str:
        """Return XNAT version string to validate connectivity.

        Queries ``/xapi/siteConfig/buildInfo`` and returns the ``version`` field
        or ``"unknown"`` if not present.
        """
        r = self.interface.get("/xapi/siteConfig/buildInfo", timeout=self.http_timeouts)
        r.raise_for_status()
        data = r.json() or {}
        return data.get(
            "version",
            "Version data not available, please verify manually and troubleshoot if needed.",
        )

    def add_scan(
        self,
        project: str,
        subject: str,
        session: str,
        *,
        xsi_type: str = "xnat:mrScanData",
        scan_type: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> str:
        """Create a scan under an image session with the next numeric scan ID.

        - Computes next ID as max(existing IDs) + 1; uses "1" if none exist.
        - ``xsi_type`` is required by XNAT (default: xnat:mrScanData).
        - Optional ``scan_type`` sets ``{xsi_type}/type`` (e.g., T1, T2).
        - ``params`` can include additional Scan Data REST XML Path parameters.

        Returns the new scan ID as a string.
        """
        # Best-effort ensure existence of container entities
        self.ensure_subject(project, subject, auto_create=True)
        self.ensure_session(project, subject, session)

        # 1) List existing scans to determine next ID
        sess = (
            self.interface.select.project(project).subject(subject).experiment(session)
        )
        scans_coll = sess.scans()
        try:
            scan_ids = scans_coll.get("ID")
        except Exception:
            scan_ids = scans_coll.get()
        existing_ids: list[int] = []
        for sid in scan_ids or []:
            try:
                existing_ids.append(int(str(sid)))
            except Exception:
                continue
        next_id = (max(existing_ids) + 1) if existing_ids else 1
        scan_id = str(next_id)

        # 2) Create the scan with required xsiType and optional params
        scan_obj = sess.scan(scan_id)
        # Create scan (no-op if exists)
        if not scan_obj.exists():
            scan_obj.insert(scans=xsi_type)
        # Optionally set type and any additional attributes
        try:
            if scan_type:
                scan_obj.attrs.set(f"{xsi_type}/type", scan_type)
            if params:
                scan_obj.attrs.mset(params)
        except Exception:
            pass
        self.log.info(f"Created scan {scan_id} in session {session}")
        return scan_id

    def upload_scan_resource(
        self,
        *,
        project: str,
        subject: str,
        session: str,
        scan_id: str,
        resource_label: str,
        file_path: Path,
        remote_name: Optional[str] = None,
    ) -> None:
        """Upload a single file to a scan resource using one PUT with inbody=true.

        If ``remote_name`` is not provided, the local filename is used.
        """
        if not file_path.exists() or not file_path.is_file():
            raise ValueError(f"File not found: {file_path}")

        # Best-effort ensure project containers exist; scan is assumed to exist
        self.ensure_subject(project, subject, auto_create=True)
        self.ensure_session(project, subject, session)

        base = f"/data/projects/{project}/subjects/{subject}/experiments/{session}/scans/{quote(str(scan_id))}"
        remote = quote(remote_name or file_path.name)
        url = f"{base}/resources/{quote(resource_label)}/files/{remote}?inbody=true"

        log = logging.getLogger(f"{session}:{scan_id}:{resource_label}")
        size_mb = file_path.stat().st_size / (1024 * 1024)
        log.info(
            f"Uploading file {file_path} ({size_mb:.1f} MB) → scan {scan_id} resource {resource_label}/{remote}"
        )
        with open(file_path, "rb") as f:
            r = self.interface.put(
                url,
                data=f,
                headers={"Content-Type": "application/octet-stream"},
                timeout=self.http_timeouts,
            )
        r.raise_for_status()
        log.info(f"Scan resource file upload OK ({r.status_code})")

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

        imp_url = "/data/services/import"
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

            resp = self.interface.post(
                imp_url,
                params=params,
                files=files,
                timeout=self.http_timeouts,
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
        base = f"/data/projects/{project}/subjects/{subject}/experiments/{session}"
        uploaded = 0
        failed = 0
        for path in sorted(local_dir.rglob("*")):
            if not path.is_file():
                continue
            rel_path = path.relative_to(local_dir).as_posix()
            url = f"{base}/resources/{quote(resource_label)}/files/{quote(rel_path)}?inbody=true"
            try:
                with open(path, "rb") as f:
                    r = self.interface.put(
                        url,
                        data=f,
                        headers={"Content-Type": "application/octet-stream"},
                        timeout=self.http_timeouts,
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

        base = f"/data/projects/{project}/subjects/{subject}/experiments/{session}"
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
                r = self.interface.put(
                    url,
                    data=f,
                    headers={"Content-Type": "application/zip"},
                    timeout=self.http_timeouts,
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
        with self.interface.get(url, stream=True, timeout=self.http_timeouts) as r:
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
        base = f"/data/projects/{project}/subjects/{subject}/experiments/{session}"
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
        # 1) list resources using object API
        sess = (
            self.interface.select.project(project).subject(subject).experiment(session)
        )
        try:
            labels = sess.resources().get("label")
        except Exception:
            # Fallback if label accessor is not supported; fetch all and extract names
            labels = [r for r in (sess.resources().get() or [])]
        base = f"/data/projects/{project}/subjects/{subject}/experiments/{session}"
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
        base = f"/data/projects/{project}/subjects/{subject}/experiments/{session}"
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

        base = f"/data/projects/{project}/subjects/{subject}/experiments/{session}"
        remote = quote(remote_name or file_path.name)
        url = f"{base}/resources/{quote(resource_label)}/files/{remote}?inbody=true"
        log = logging.getLogger(f"{session}:{resource_label}")
        size_mb = file_path.stat().st_size / (1024 * 1024)
        log.info(
            f"Uploading file {file_path} ({size_mb:.1f} MB) → {resource_label}/{remote}"
        )
        with open(file_path, "rb") as f:
            r = self.interface.put(
                url,
                data=f,
                headers={"Content-Type": "application/octet-stream"},
                timeout=self.http_timeouts,
            )
        r.raise_for_status()
        log.info(f"File upload OK ({r.status_code})")

    def list_scans(
        self,
        project: str,
        subject: str,
        session: str,
    ) -> list[str]:
        """Return the list of scan IDs for a given session.

        Uses the object API to enumerate scans and normalizes IDs to strings.
        """
        sess = (
            self.interface.select.project(project).subject(subject).experiment(session)
        )
        scans_coll = sess.scans()
        try:
            ids = scans_coll.get("ID") or []
        except Exception:
            ids = scans_coll.get() or []
        return [str(s) for s in ids]

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

        # First, get list of available scans for this session via object API
        try:
            available_scan_ids = self.list_scans(project, subject, session)

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

            # Delete each scan using object API
            deleted_scans = []
            for scan_id in scans_to_delete:
                try:
                    self.log.info(f"Deleting scan {scan_id}...")
                    self.interface.select.project(project).subject(subject).experiment(
                        session
                    ).scan(scan_id).delete(delete_files=True)
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
