## Resource Upload Methods vs XNAT Requirements

### Key Differences: Resource Upload vs DICOM Upload

| Aspect | **Resource Upload** | **DICOM Upload** |
|--------|-------------------|------------------|
| **API Endpoint** | `/resources/{label}/files/{name}` | `/services/import` |
| **HTTP Method** | `PUT` | `POST` |
| **Purpose** | Extract files to resource | Import DICOM sessions |
| **Extraction** | `?extract=true` | Built-in DICOM processing |
| **Body Format** | Raw binary (`inbody=true`) | Multipart form (`files=`) |
| **Scope** | Single resource catalog | Entire session/scans |