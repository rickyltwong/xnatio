#!/bin/bash

# Script to upload Arterial folders as resources from CURB_NABI studies to XNAT
# Project: NBO01_CMH
# Only processes CURB_NABI folders that have Arterial subdirectories

# Note: removed 'set -e' as it interferes with arithmetic operations

STAGING_DIR="${STAGING_DIR:-/path/to/staging_area}"
PROJECT="${PROJECT:-DEMO_PRJ}"
RESOURCE="${RESOURCE:-ARTERIAL}"
ENV="${ENV:-dev}"

echo "Starting CURB_NABI Arterial resource uploads..."
echo "Staging directory: $STAGING_DIR"
echo "Project: $PROJECT"
echo "Resource: $RESOURCE"
echo "Environment: $ENV"
echo "----------------------------------------"

# Counter for processed folders
count=0
skipped_missing_arterial=0

# Loop through all CURB_NABI* folders
for folder in "$STAGING_DIR"/CURB_NABI*; do
    # Check if it's actually a directory
    if [[ ! -d "$folder" ]]; then
        continue
    fi
    
    # Extract folder name
    folder_name=$(basename "$folder")
    echo "Processing: $folder_name"
    
    # Extract YYYYGXXX pattern from folder name
    if [[ "$folder_name" =~ CURB_NABI_([0-9]{4}G[0-9]{3})$ ]]; then
        study_id="${BASH_REMATCH[1]}"
    else
        echo "  WARNING: Could not extract study ID from $folder_name, skipping"
        continue
    fi
    
    # Check if Arterial folder exists
    arterial_folder="$folder/Arterial"
    if [[ ! -d "$arterial_folder" ]]; then
        echo "  SKIPPING: $study_id (no Arterial folder found)"
        ((skipped_missing_arterial++))
        continue
    fi
    
    # Construct XNAT identifiers
    subject="NBO01_CMH_$study_id"
    session="NBO01_CMH_${study_id}_01_SE01_PET"
    
    echo "  Study ID: $study_id"
    echo "  Subject: $subject"
    echo "  Session: $session"
    echo "  Arterial folder: $arterial_folder"
    
    # Run the upload-resource command
    echo "  Executing Arterial resource upload..."
    if uv run xnatio upload-resource "$PROJECT" "$subject" "$session" "$RESOURCE" "$arterial_folder" --env "$ENV" -v; then
        echo "  ✓ SUCCESS: Arterial upload completed for $study_id"
        ((count++))
    else
        echo "  ✗ FAILED: Arterial upload failed for $study_id"
        exit 1
    fi
    
    echo "  ----------------------------------------"
done

echo "CURB_NABI Arterial resource upload script completed successfully!"
echo "Total Arterial folders uploaded: $count"
echo "Skipped folders missing Arterial: $skipped_missing_arterial" 