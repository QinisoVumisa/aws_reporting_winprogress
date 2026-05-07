#!/bin/bash

## ================Get Account Context ============================
#calleridentity=`aws sts get-caller-identity --output json 2> /dev/null` ## Get account id.
#if [[ ${#calleridentity} -gt 2 ]] ## Make sure we got a return value
#    then accountid=`jq -r '.Account' <<< $calleridentity 2> /dev/null`
#fi
#printf "# -------------------------------------------------------------------------\nFetching account context is complete\n# -------------------------------------------------------------------------\n"

export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10


printf "\n================================================================================\n"
printf "RECOMMENDED HIGH PRIORITY REMEDIATION SECTION\n-\n"
printf "The following failures are considered TOP PRIORITY for remedediation by the Synthesis Security Team\n"
printf "================================================================================\n"


printf "\n======\nEC2.19 - Security groups with sensitive ports open to public internet\n======\n"
aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"EC2.19","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' |awk 'NR<3{print$0;next}{print $0| "sort -r"}'

printf "\n======\nAWS: S3.8 - Block S3 Public Access needs to be enabled on each bucket\n======\n"
aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"S3.8","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' |awk 'NR<3{print$0;next}{print $0| "sort -r"}'

printf "\n======\nAWS: S3.1 - Block S3 Public Access needs to be enabled in each account\n======\n"
aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"S3.1","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' |awk 'NR<3{print$0;next}{print$0| "sort -r"}'

printf "\n======\nEC2.7 - EBS default encryption setting should be enabled\n======\n"
aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"EC2.7","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id,.Resources[].Region, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' |awk 'NR<3{print$0;next}{print $0| "sort -r"}'


printf "\n======\nIAM.5 - IAM users with console access that don't have MFA/2FA\n======\n"
aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"IAM.5","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' |awk 'NR<3{print$0;next}{print $0| "sort -r"}' | sort | uniq

# NOTE these checks need to be MANUALLY excluded from the remaing compliance checks to prevent duplicates

#printf "\n===\nEnd of TOP PRIORITY section. Resuming standard compliance checks. \n===\n"









