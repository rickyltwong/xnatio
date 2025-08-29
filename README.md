# XNAT IO

CLI utilities for interacting with CAMH XNAT instance with focus on admin use cases.

Inspired by [niptools](https://gitlab.camh.ca/xnat/niptools).

## Install

### From Source (Recommended)

```bash
git clone https://gitlab.camh.ca/xnat/xnatio.git
cd xnatio
pip install .
```

### For Development

```bash
git clone https://gitlab.camh.ca/xnat/xnatio.git
cd xnatio

# Option 1: Using uv (fast)
uv sync
uv run xnatio --help

# Option 2: Using pip with virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
xnatio --help
```

### Using pipx (Isolated Installation)

```bash
git clone https://gitlab.camh.ca/xnat/xnatio.git
cd xnatio
pipx install .
xnatio --help
```

## Programmatic Usage

You can also use xnatio as a Python library:

```python
from xnatio import XNATClient, load_config

# Load configuration from .env file
config = load_config()

# Create XNAT client
client = XNATClient.from_config(config)

# Use client methods
client.upload_dicom_zip(
    archive_path,
    project="PROJECT_ID", 
    subject="SUBJECT_ID",
    session="SESSION_ID"
)
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
- Use `--env dev` to load `.env.dev` instead of `.env`, `--env test` to load `.env.test`, `--env prod` to load `.env.prod`.

## CLI

### Commands

- **upload-dicom**: Upload a DICOM session from a ZIP/TAR(.gz)/TGZ archive or a directory via the import service
- **download-session**: Download scans and all session resources; optional assessors and reconstructions; can auto-extract and clean up zips
- **extract-session**: Extract all zips in a session directory into structured folders
- **upload-resource**: Upload a local file or directory into a session resource. Directories are zipped locally and extracted server-side
- **create-project**: Create a new project in XNAT (ID, secondary_ID, name set to the provided value)
- **delete-scans**: Delete specific scan files or all scans for a given project, subject, and session (use with caution!)

### Help

```bash
xnatio --help
xnatio upload-dicom --help
xnatio download-session --help
xnatio extract-session --help
xnatio upload-resource --help
xnatio create-project --help
xnatio delete-scans --help
```

### Examples

Upload a DICOM session from an archive:

```bash
xnatio upload-dicom TST01_CMH TST01_CMH_00000001 TST01_CMH_00000001_01_SE01_MR \
  /path/to/ARCHIVE.zip --env test -v
```

Upload a DICOM session from a directory (auto-zipped to a temporary file first):

```bash
xnatio upload-dicom TST01_CMH TST01_CMH_00000001 TST01_CMH_00000001_01_SE01_MR \
  /path/to/dicom_dir --env test -v
```

Download a session into `outdir/SESSION_LABEL`, include assessors/recons, unzip and remove zips:

```bash
xnatio download-session TST01_CMH TST01_CMH_00000001 TST01_CMH_00000001_01_SE01_MR outdir \
  --include-assessors --include-recons --unzip --env dev -v
```

Upload a directory as a session resource (zipped and extracted server-side):

```bash
xnatio upload-resource TST01_CMH TST01_CMH_00000001 TST01_CMH_00000001_01_SE01_MR \
  BIDS /path/to/bids_directory --env test -v
```

Delete scans for a session:

```bash
# Delete all scans (interactive confirmation required)
xnatio delete-scans TST01_CMH TST01_CMH_00000001 TST01_CMH_00000001_01_SE01_MR \
  --scan "*" --env test -v

# Delete specific scans by ID
xnatio delete-scans TST01_CMH TST01_CMH_00000001 TST01_CMH_00000001_01_SE01_MR \
  --scan "1,2,3,4,6" --env test -v

# Skip confirmation prompt with --confirm flag
xnatio delete-scans TST01_CMH TST01_CMH_00000001 TST01_CMH_00000001_01_SE01_MR \
  --scan "*" --confirm --env test -v
```

## Requirements

- Python 3.8 or higher
- Access to an XNAT server
- Valid XNAT credentials

## Notes

- Accepted upload formats: `.zip`, `.tar`, `.tar.gz`, `.tgz`. `upload-dicom` also accepts a directory and will zip it temporarily.
- Session downloads are parallelized and show byte-progress logs if `-v` is set.
- Environment variables can be exported directly instead of `.env` if preferred.
- Use `--env dev` to load `.env.dev` instead of `.env` for different environments.
