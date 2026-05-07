#!/bin/bash


# AWS takes forever to updat the security hub findings list so we need a good three minute delay here before we can start changing the worklow.
#
#

printf "\n"
#echo Waiting 10 seconds for AWS to register sample guardduty finding.
#sleep 10

samplefindingid=$(aws securityhub get-findings --filters '{"Title":[{"Value":"Amazon S3 Block Public Access was disabled for the S3 bucket GeneratedFindingS3Bucket.","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}]}'| jq -r '.Findings[].Id')

sleep 1

samplefindingproductarn=$(aws securityhub get-findings --filters '{"Title":[{"Value":"Amazon S3 Block Public Access was disabled for the S3 bucket GeneratedFindingS3Bucket.","Comparison":"EQUALS"}]}'| jq -r '.Findings[].ProductArn')

sleep 1

if [[ -z "$samplefindingid" ]]; then
	printf "\n"
	echo Problem resolving sample guardduty finding. Sample finding not found in Security Hub, or has already been marked as RESOLVED.
else      	
#	echo Marking sample guardduty finding as resolved.
	aws securityhub batch-update-findings --finding-identifiers Id="$samplefindingid",ProductArn="$samplefindingproductarn" --workflow Status="RESOLVED" > /dev/null

fi



