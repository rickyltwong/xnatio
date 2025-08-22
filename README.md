# XNAT IO

CLI utilities for interacting with CAMH XNAT instance as an admin.

Inspired by [niptools](https://gitlab.camh.ca/xnat/niptools).

## Install

Using uv (recommended):

```bash
uv sync
uv run xnatio --help
```

From PyPI (once published):

```bash
pip install xnatio
```

From Git (main branch):

```bash
pip install git+https://gitlab.camh.ca/xnat/xnatio.git@main#egg=xnatio
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

### Help

```bash
uv run xnatio --help
uv run xnatio upload-dicom --help
uv run xnatio download-session --help
uv run xnatio extract-session --help
uv run xnatio upload-resource --help
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
  --include-assessors --include-recons --unzip -v
```

Extract a previously downloaded session directory:

```bash
uv run xnatio extract-session outdir/NAT01_ROM_00000001_01_SE01_MR -v
```

Upload a local directory to a session resource (zipped automatically, extracted on server):

```bash
uv run xnatio upload-resource NAT01_ROM NAT01_ROM_00000001 NAT01_ROM_00000001_01_SE01_MR BIDS \
  tests/data/nat01/NAT01_ROM_00000001_01_SE01_MR/BIDS -v
```

Upload a single file to `resources/MISC`:

```bash
uv run xnatio upload-resource NAT01_ROM NAT01_ROM_00000001 NAT01_ROM_00000001_01_SE01_MR MISC \
  /path/to/file.txt -v
```

## Notes

- Accepted upload formats: `.zip`, `.tar`, `.tar.gz`, `.tgz`. `upload-dicom` also accepts a directory and will zip it temporarily.
- Session downloads are parallelized and show byte-progress logs if `-v` is set.
- Environment variables can be exported directly instead of `.env` if preferred.
