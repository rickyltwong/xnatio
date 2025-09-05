#!/bin/bash

# Script to upload Arterial folders as resources to XNAT
# Only processes SDM8_CASDY folders that have Arterial subdirectories
# Excludes: 2024G155, 2024G182, 2024G191 and NO_ARTERIAL folders

# Note: removed 'set -e' as it interferes with arithmetic operations

STAGING_DIR="${STAGING_DIR:-/path/to/staging_area}"
PROJECT="${PROJECT:-DEMO_PRJ}"
RESOURCE="${RESOURCE:-ARTERIAL}"
ENV="${ENV:-dev}"

# Array of folders to exclude
EXCLUDE_FOLDERS=()

echo "Starting Arterial resource uploads..."
echo "Staging directory: $STAGING_DIR"
echo "Project: $PROJECT"
echo "Resource: $RESOURCE"
echo "Environment: $ENV"
echo "Excluded folders: ${EXCLUDE_FOLDERS[*]}"
echo "----------------------------------------"

# Counter for processed folders
count=0
skipped_no_arterial=0
skipped_missing_arterial=0

# Loop through all SDM8_CASDY* folders
for folder in "$STAGING_DIR"/SDM8_CASDY*; do
    # Check if it's actually a directory
    if [[ ! -d "$folder" ]]; then
        continue
    fi
    
    # Extract folder name
    folder_name=$(basename "$folder")
    echo "Processing: $folder_name"
    
    # Skip NO_ARTERIAL folders
    if [[ "$folder_name" == *"NO_ARTERIAL"* ]]; then
        echo "  SKIPPING: $folder_name (NO_ARTERIAL folder)"
        ((skipped_no_arterial++))
        continue
    fi
    
    # Extract YYYYGXXX pattern from folder name
    if [[ "$folder_name" =~ SDM8_CASDY.*([0-9]{4}G[0-9]{3})$ ]]; then
        study_id="${BASH_REMATCH[1]}"
    else
        echo "  WARNING: Could not extract study ID from $folder_name, skipping"
        continue
    fi
    
    # Check if this study ID should be excluded
    skip=false
    for exclude in "${EXCLUDE_FOLDERS[@]}"; do
        if [[ "$study_id" == "$exclude" ]]; then
            echo "  SKIPPING: $study_id (in exclusion list)"
            skip=true
            break
        fi
    done
    
    if [[ "$skip" == true ]]; then
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
    subject="CAS01_CMH_$study_id"
    session="CAS01_CMH_${study_id}_01_SE01_PET"
    
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

echo "Arterial resource upload script completed successfully!"
echo "Total Arterial folders uploaded: $count"
echo "Skipped NO_ARTERIAL folders: $skipped_no_arterial"
echo "Skipped folders missing Arterial: $skipped_missing_arterial" 