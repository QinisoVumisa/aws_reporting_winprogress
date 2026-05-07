#!/bin/bash

# this script does the following: If a sample finding already exists in security hub - mark the workflow as NEW
# In any case - generate a new finding!



auditdetectorid=$(aws guardduty list-detectors |jq -r '.DetectorIds[]')

aws guardduty create-sample-findings --detector-id $auditdetectorid --finding-types Policy:S3/BucketBlockPublicAccessDisabled

sleep 1

samplefindingid=$(aws securityhub get-findings --filters '{"Title":[{"Value":"Amazon S3 Block Public Access was disabled for the S3 bucket GeneratedFindingS3Bucket.","Comparison":"EQUALS"}]}'| jq -r '.Findings[0].Id')

sleep 1

samplefindingproductarn=$(aws securityhub get-findings --filters '{"Title":[{"Value":"Amazon S3 Block Public Access was disabled for the S3 bucket GeneratedFindingS3Bucket.","Comparison":"EQUALS"}]}'| jq -r '.Findings[0].ProductArn')

sleep 1

if [[ -z "$samplefindingid" ]]; then
        printf "\n"
        echo Creating sample GuardDuty incident to trigger ITSM test
	aws guardduty create-sample-findings --detector-id $auditdetectorid --finding-types Policy:S3/BucketBlockPublicAccessDisabled

	sleep 1
	
else	
	
	echo Existing Sample GuardDuty finding detected. Setting workflow as NEW to trigger a test incident to the ITSM process.

        aws securityhub batch-update-findings --finding-identifiers Id="$samplefindingid",ProductArn="$samplefindingproductarn" --workflow Status="NEW" > /dev/null

fi








