# XNAT IO

CLI utilities for interacting with an XNAT instance with a focus on admin use cases.

Inspired by niptools 

## Install

### From GitHub (pip, no clone)

```bash
# Latest from main
python -m pip install "xnatio @ git+https://github.com/rickyltwong/xnatio.git@main"

# Or pin to a tag (recommended once you create one)
python -m pip install "xnatio @ git+https://github.com/rickyltwong/xnatio.git@v0.1.0"

# Test the installation
xnatio --help
# or use the shorter alias:
xio --help
```

### From Source (Recommended)

```bash
git clone https://github.com/rickyltwong/xnatio.git
cd xnatio
pip install .

# Test the installation
xnatio --help
# or use the shorter alias:
xio --help
```

### For Development

```bash
git clone https://github.com/rickyltwong/xnatio.git
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
# No clone (install directly from GitHub)
pipx install "xnatio@git+https://github.com/rickyltwong/xnatio.git@main"
# Or pin to a tag (recommended once you create one)
pipx install "xnatio@git+https://github.com/rickyltwong/xnatio.git@v0.1.0"
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
- **list-scans**: List scan IDs for a session
- **refresh-catalogs**: Refresh catalog XMLs for all experiments in a project with optional checksum/delete/append/populateStats actions

> **Tip**: You can use the shorter alias `xio` instead of `xnatio` for all commands (e.g., `xio --help`, `xio upload-dicom`, etc.)

### Help

```bash
xnatio --help
# or use the shorter alias:
xio --help

xnatio upload-dicom --help
xnatio download-session --help
xnatio extract-session --help
xnatio upload-resource --help
xnatio create-project --help
xnatio delete-scans --help
xnatio list-scans --help
xnatio refresh-catalogs --help
```

### Examples

Upload a DICOM session from an archive:

```bash
xnatio upload-dicom DEMO_PRJ DEMO_SUBJ DEMO_SESS \
  /path/to/ARCHIVE.zip --env test -v

# or using the shorter alias:
xio upload-dicom DEMO_PRJ DEMO_SUBJ DEMO_SESS \
  /path/to/ARCHIVE.zip --env test -v
```

Upload a DICOM session from a directory (auto-zipped to a temporary file first):

```bash
xio upload-dicom DEMO_PRJ DEMO_SUBJ DEMO_SESS \
  /path/to/dicom_dir --env test -v
```

Download a session into `outdir/SESSION_LABEL`, include assessors/recons, unzip and remove zips:

```bash
xio download-session DEMO_PRJ DEMO_SUBJ DEMO_SESS outdir \
  --include-assessors --include-recons --unzip --env dev -v
```

Upload a directory as a session resource (zipped and extracted server-side):

```bash
xio upload-resource DEMO_PRJ DEMO_SUBJ DEMO_SESS \
  BIDS /path/to/bids_directory --env test -v
```

Delete scans for a session:

```bash
# Delete all scans (interactive confirmation required)
xio delete-scans DEMO_PRJ DEMO_SUBJ DEMO_SESS \
  --scan "*" --env test -v

# Delete specific scans by ID
xio delete-scans DEMO_PRJ DEMO_SUBJ DEMO_SESS \
  --scan "1,2,3,4,6" --env test -v

# Skip confirmation prompt with --confirm flag
xio delete-scans DEMO_PRJ DEMO_SUBJ DEMO_SESS \
  --scan "*" --confirm --env test -v

# Refresh catalogs for all experiments in a project (e.g., add new files, compute checksums)
xio refresh-catalogs DEMO_PRJ --option append --option checksum --env test -v
```

## Requirements

- Python 3.8 or higher
- Access to an XNAT server
- Valid XNAT credentials

## Notes

- Accepted upload formats: `.zip`, `.tar`, `.tar.gz`, `.tgz`. `upload-dicom` also accepts a directory and will zip it temporarily.
- Session downloads are parallelized and show byte-progress logs if `-v` is set.
- Environment variables can be exported directly instead of `.env` if preferred.
- Use `--env dev` to load `.env.dev` instead of `.env`, `--env test` to load `.env.test`, `--env prod` to load `.env.prod`.
