#!/bin/bash

# Script to upload CURB_NABI* folders to XNAT
# Project: NBO01_CMH

# Note: removed 'set -e' as it interferes with arithmetic operations

STAGING_DIR="${STAGING_DIR:-/path/to/staging_area}"
PROJECT="${PROJECT:-DEMO_PRJ}"
ENV="${ENV:-dev}"

EXCLUDE_FOLDERS=("CURB_NABI_2024G133" "CURB_NABI_2024G149" "CURB_NABI_2024G163" "CURB_NABI_2024G178" "CURB_NABI_2024G186" "CURB_NABI_2024G190" "CURB_NABI_2024G187" "CURB_NABI_2024G203")

echo "Starting CURB_NABI DICOM uploads..."
echo "Staging directory: $STAGING_DIR"
echo "Project: $PROJECT"
echo "Environment: $ENV"
echo "Excluded folders: ${EXCLUDE_FOLDERS[*]}"
echo "----------------------------------------"

# Counter for processed folders
count=0

# Loop through all CURB_NABI* folders
for folder in "$STAGING_DIR"/CURB_NABI*; do
    # Check if it's actually a directory
    if [[ ! -d "$folder" ]]; then
        continue
    fi
    
    # Extract folder name
    folder_name=$(basename "$folder")
    
    # Skip excluded folders
    if [[ " ${EXCLUDE_FOLDERS[*]} " == *" $folder_name "* ]]; then
        echo "  SKIPPING: $folder_name (in exclusion list)"
        continue
    fi
    echo "Processing: $folder_name"
    
    # Extract YYYYGXXX pattern from folder name
    if [[ "$folder_name" =~ CURB_NABI_([0-9]{4}G[0-9]{3})$ ]]; then
        study_id="${BASH_REMATCH[1]}"
    else
        echo "  WARNING: Could not extract study ID from $folder_name, skipping"
        continue
    fi
    
    # Construct XNAT identifiers
    subject="NBO01_CMH_$study_id"
    session="NBO01_CMH_${study_id}_01_SE01_PET"
    
    echo "  Study ID: $study_id"
    echo "  Subject: $subject"
    echo "  Session: $session"
    echo "  Folder: $folder"
    
    # Run the upload command
    echo "  Executing DICOM upload..."
    if uv run xnatio upload-dicom "$PROJECT" "$subject" "$session" "$folder" --env "$ENV" -v; then
        echo "  ✓ SUCCESS: DICOM upload completed for $study_id"
        ((count++))
    else
        echo "  ✗ FAILED: DICOM upload failed for $study_id"
        exit 1
    fi
    
    echo "  ----------------------------------------"
done

echo "CURB_NABI DICOM upload script completed successfully!"
echo "Total folders processed: $count" 