from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import quote

import requests
from pyxnat import Interface
import zipfile
import tempfile


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
        default_project: Optional[str] = None,
        verify_tls: bool = True,
        http_timeouts: Tuple[int, int] = (60, 72000),
        logger: Optional[logging.Logger] = None,
    ):
        """Create a new XNAT client.

        Parameters
        - server: Base URL of the XNAT server (e.g., https://xnat.example.org)
        - username: XNAT username
        - password: XNAT password
        - default_project: Optional project label used for `parse_ids` when
          explicit overrides are not supplied
        - verify_tls: Whether to verify TLS certificates
        - http_timeouts: (connect_timeout_seconds, read_timeout_seconds)
        - logger: Optional logger; if None, a module logger is used
        """
        self.server = server.rstrip("/")
        self.username = username
        self.password = password
        self.default_project = default_project
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

        Expected keys in cfg: server, user, password, project.
        """
        return cls(
            server=str(cfg["server"]),
            username=str(cfg["user"]),
            password=str(cfg["password"]),
            default_project=str(cfg.get("project", "")) or None,
            verify_tls=bool(cfg.get("verify_tls", True)),
        )

    @staticmethod
    def parse_ids(stem: str, cfg_project: str) -> Tuple[str, str, str]:
        """Parse IDs from an archive stem using the configured project prefix.

        Expected filename stem format: "<PROJECT>_<SUBJECT>_<SESSION>" where
        <PROJECT> equals `cfg_project` (may contain underscores).

        Returns (project, subject, session).
        Raises ValueError if the stem doesn't match the expected format.
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

    def ensure_subject(
        self, project: str, subject: str, *, auto_create: bool = True
    ) -> None:
        """Ensure a subject exists in the given project.

        If `auto_create` is True, attempt to create the subject (no-op if it exists).
        Raises RuntimeError if creation is disabled and subject might be missing.
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
    ) -> None:
        """Upload a DICOM ZIP/TAR archive to the XNAT import service.

        Ensures the subject and session exist, then POSTs the archive to
        `/data/services/import` with the given handler.
        """
        log = logging.getLogger(archive.name)
        self.ensure_subject(project, subject, auto_create=True)
        self.ensure_session(project, subject, session)

        imp_url = f"{self.server}/data/services/import"
        log.info(
            f"Starting upload of {archive.name} ({archive.stat().st_size / (1024 * 1024 * 1024):.1f} GB)"
        )

        with open(archive, "rb") as f:
            files = {"file": (archive.name, f)}
            data = {
                "project": project,
                "subject": subject,
                "session": session,
                "inbody": "true",
                "import-handler": import_handler,
                "Ignore-Unparsable": "true" if ignore_unparsable else "false",
            }
            resp = self.http.post(
                imp_url,
                files=files,
                data=data,
                timeout=self.http_timeouts,
                stream=True,
            )
            resp.raise_for_status()
            log.info(f"DICOM import OK ({resp.status_code})")

    def upload_archive(
        self,
        archive: Path,
        *,
        project: Optional[str] = None,
        subject: Optional[str] = None,
        session: Optional[str] = None,
        import_handler: str = "DICOM-zip",
        ignore_unparsable: bool = True,
    ) -> None:
        """Upload a ZIP/TAR archive as a DICOM package via the import service.

        If all of `project`, `subject`, and `session` are provided, they are used.
        Otherwise, IDs are parsed from the archive's stem using `self.default_project`.

        Parameters
        - archive: Path to the .zip/.tar/.tar.gz/.tgz archive
        - project, subject, session: Optional explicit IDs. All three must be set to override parsing
        - import_handler: XNAT import handler (default "DICOM-zip")
        - ignore_unparsable: Whether to ignore unparsable files for import
        """
        if project and subject and session:
            proj, subj, sess = project, subject, session
        else:
            if not self.default_project:
                raise ValueError(
                    "No project overrides provided and no default_project set to parse IDs"
                )
            proj, subj, sess = self.parse_ids(
                archive.stem, cfg_project=self.default_project
            )

        self.upload_dicom_zip(
            archive,
            project=proj,
            subject=subj,
            session=sess,
            import_handler=import_handler,
            ignore_unparsable=ignore_unparsable,
        )

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
