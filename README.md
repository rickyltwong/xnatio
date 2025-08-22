# XNAT IO

CLI utilities for interacting with CAMH XNAT instance as an admin.

Inspired by [niptools](https://gitlab.camh.ca/xnat/niptools).

## Install

- Recommended: install from the GitLab Package Registry.
- Alternative: use pipx for an isolated CLI, or install from source.

### A) GitLab Package Registry (recommended)

1) Get the project ID from the GitLab project sidebar. Example: `12345`.

2) Get credentials:
- Deploy Token (recommended): scope `read_package_registry`. Use the provided username `gitlab+deploy-token-<id>` and the token as the password.
- Or a Personal Access Token: scope `read_api`. Use username `oauth2` and the token as the password.

3) Install (inline credentials):

```bash
pip install \
  --index-url https://USERNAME:PASSWORD@gitlab.camh.ca/api/v4/projects/PROJECT_ID/packages/pypi/simple \
  --extra-index-url https://pypi.org/simple \
  xnatio
```

Or configure pip once and then install:

```bash
pip config set global.index-url "https://USERNAME:PASSWORD@gitlab.camh.ca/api/v4/projects/PROJECT_ID/packages/pypi/simple"
pip config set global.extra-index-url "https://pypi.org/simple"

pip install xnatio
```

Replace `USERNAME`/`PASSWORD` and `PROJECT_ID` as described above.

### B) pipx (isolated CLI)

```bash
pipx install \
  --index-url https://USERNAME:PASSWORD@gitlab.camh.ca/api/v4/projects/PROJECT_ID/packages/pypi/simple \
  --extra-index-url https://pypi.org/simple \
  xnatio

# Use
xnatio --help
```

### C) From source

Using uv (fast):

```bash
uv sync
uv run xnatio --help
```

Using pip (virtualenv recommended):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
xnatio --help
```

## Configure

Create a `.env` (or `.env.dev`) at the project root with:

```
XNAT_SERVER=https://your-xnat.example.org
XNAT_USERNAME=your_user
XNAT_PASSWORD=your_password
# optional
XNAT_VERIFY_TLS=true
```

- Set `XNAT_VERIFY_TLS=false` for dev servers with self-signed or untrusted certs.
- Use `--env dev` to load `.env.dev` instead of `.env`.

## CLI

### Commands

- **upload-dicom**: Upload a DICOM session from a ZIP/TAR(.gz)/TGZ archive or a directory via the import service
- **download-session**: Download scans and all session resources; optional assessors and reconstructions; can auto-extract and clean up zips
- **extract-session**: Extract all zips in a session directory into structured folders
- **upload-resource**: Upload a local file or directory into a session resource. Directories are zipped locally and extracted server-side
- **create-project**: Create a new project in XNAT (ID, secondary_ID, name set to the provided value)

### Help

```bash
uv run xnatio --help
uv run xnatio upload-dicom --help
uv run xnatio download-session --help
uv run xnatio extract-session --help
uv run xnatio upload-resource --help
uv run xnatio create-project --help
```

### Examples

Upload a DICOM session from an archive:

```bash
uv run xnatio upload-dicom NAT01_ROM NAT01_ROM_00000001 NAT01_ROM_00000001_01_SE01_MR \
  /path/to/ARCHIVE.zip --env test -v
```

Upload a DICOM session from a directory (auto-zipped to a temporary file first):

```bash
uv run xnatio upload-dicom NAT01_ROM NAT01_ROM_00000001 NAT01_ROM_00000001_01_SE01_MR \
  /path/to/dicom_dir --env test -v
```

Download a session into `outdir/SESSION_LABEL`, include assessors/recons, unzip and remove zips:

```bash
uv run xnatio download-session NAT01_ROM NAT01_ROM_00000001 NAT01_ROM_00000001_01_SE01_MR outdir \
  --include-assessors --include-recons --unzip --env dev -v
```

### Install from GitLab Package Registry

Once CI publishes a release (tag), users can install directly from the GitLab Python registry:

```bash
pip install --index-url https://gitlab.camh.ca/api/v4/projects/<PROJECT_ID>/packages/pypi/simple \
            --extra-index-url https://pypi.org/simple \
            xnatio==0.1.0
```

Or configure `~/.pip/pip.conf` or `~/.pypirc` to point to the GitLab index URL and then `pip install xnatio`.

### Publishing (maintainers)

- Push a tag (e.g., `v0.1.0`) to trigger the publish job:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The pipeline builds wheels/sdist and uploads them to the project’s GitLab Package Registry using the CI job token.

## Notes

- Accepted upload formats: `.zip`, `.tar`, `.tar.gz`, `.tgz`. `upload-dicom` also accepts a directory and will zip it temporarily.
- Session downloads are parallelized and show byte-progress logs if `-v` is set.
- Environment variables can be exported directly instead of `.env` if preferred.
