#!/bin/bash

# Script to upload SDM8_CASDY* folders to XNAT (including NO_ARTERIAL folders)
# Excludes: 2024G155, 2024G182, 2024G191

# Note: removed 'set -e' as it interferes with arithmetic operations

# Configure via environment or default placeholders
STAGING_DIR="${STAGING_DIR:-/path/to/staging_area}"
PROJECT="${PROJECT:-DEMO_PRJ}"
ENV="${ENV:-dev}"

# Array of folders to exclude
EXCLUDE_FOLDERS=("2024G155" "2024G182" "2024G191" "2025G044" "2025G012")

echo "Starting SDM8_CASDY uploads..."
echo "Staging directory: $STAGING_DIR"
echo "Project: $PROJECT"
echo "Environment: $ENV"
echo "Excluded folders: ${EXCLUDE_FOLDERS[*]}"
echo "----------------------------------------"

# Counter for processed folders
count=0

# Loop through all SDM8_CASDY* folders
for folder in "$STAGING_DIR"/SDM8_CASDY*; do
    # Check if it's actually a directory
    if [[ ! -d "$folder" ]]; then
        continue
    fi
    
    # Extract folder name
    folder_name=$(basename "$folder")
    echo "Processing: $folder_name"
    
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
    
    # Construct XNAT identifiers
    subject="CAS01_CMH_$study_id"
    session="CAS01_CMH_${study_id}_01_SE01_PET"
    
    echo "  Study ID: $study_id"
    echo "  Subject: $subject"
    echo "  Session: $session"
    echo "  Folder: $folder"
    
    # Run the upload command
    echo "  Executing upload..."
    if uv run xnatio upload-dicom "$PROJECT" "$subject" "$session" "$folder" --env "$ENV" -v; then
        echo "  ✓ SUCCESS: Upload completed for $study_id"
        ((count++))
    else
        echo "  ✗ FAILED: Upload failed for $study_id"
        exit 1
    fi
    
    echo "  ----------------------------------------"
done

echo "Upload script completed successfully!"
echo "Total folders processed: $count" 