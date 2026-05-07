#!/bin/bash

export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10


# printf "===\nChecking security monitoring tools enabled\n===\n"

today=$(date +"%Y-%m-%d")
dateyesterday=$(date -v-1d '+%Y-%m-%d')


# Need to determine which regions are currently reporting security findings and alerts

calleridentity=`aws sts get-caller-identity --output json 2> /dev/null` ## Get account id.
if [[ ${#calleridentity} -gt 2 ]] ## Make sure we got a return value
    then accountid=`jq -r '.Account' <<< $calleridentity 2> /dev/null`
fi


#printf "\nTotal number of accounts as reported by AWS Organisations (Landing Zone) : "
#aws organizations list-accounts |jq '(.Accounts) | length'
#printf "\n"


printf "==========================================================================================\n"
printf "MONITORING SECTION\n-\nConfirming security monitoring is enabled and working in all accounts\n"
printf "=========================================================================================="

printf "\n\n"
#printf "Number of accounts reported by AWS Organisations (Root Account)"

printf "Number of AWS accounts reporting security events:\t"
accountsreporting=$(aws securityhub list-members |jq '.Members| length +1')
printf "$accountsreporting\n"


printf "Number of AWS regions reporting security events:\t"
numberofregions=$(aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "IAM.6","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.Resources[]|.Region' | sort| uniq |wc -l)
printf "$numberofregions\n===\n"

totalaccountsregions=$((accountsreporting*numberofregions))

#printf "Security Hub is monitoring security findings and events from the following AWS regions:\n"
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "IAM.6","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.Resources[]|.Region' | sort| uniq | tee identified-regions-$accountid.txt

aws securityhub get-findings --output json  --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"ComplianceSecurityControlId":[{"Value":"IAM.6","Comparison":"EQUALS"}],"ProductName":[{"Value":"Security Hub","Comparison":"EQUALS"}]}'| jq -r '.Findings[]|.Region' | sort | uniq | tee identified-regions-$accountid.txt

# PULL COMPLIANCE TABLE FOR PAGE 1

#printf "\n"
#printf "Number of regions failing CloudTrail.1 check (AWS Audit Trail):\t\t\t\t"
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "CloudTrail.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings|length'

#printf "Number of regions failing Config.1 check (AWS Configuration Tracking):\t\t\t\t"
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "Config.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings|length'


#printf "Number of regions failing GuardDuty.1 check (AWS Threat Detection):\t\t\t\t"
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "GuardDuty.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings|length'

printf "\n"

printf "The following AWS compliance standards have been enabled in the environment:\n===\n"
#aws securityhub get-findings --output json  --filters '{"ComplianceSecurityControlId": [{"Value":"IAM.6","Comparison":"EQUALS"}],"RecordState":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}]}'| jq '.Findings[]|.Compliance.AssociatedStandards[].StandardsId' | sort | uniq |tee identified-standards-$accountid.txt

aws securityhub get-findings --output json  --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"ComplianceSecurityControlId":[{"Value":"IAM.6","Comparison":"EQUALS"}],"ProductName":[{"Value":"Security Hub","Comparison":"EQUALS"}]}'| jq -r '.Findings[]|.Compliance.AssociatedStandards[].StandardsId' | sort | uniq |tee identified-standards-$accountid.txt

printf "\n"


cat identified-regions-$accountid.txt | while read -r line; do
	identifiedregionline="$line"
	cat identified-standards-$accountid.txt | while read -r line; do
		identifiedstandardsline="$line"
		gtemp=$(aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],"ComplianceSecurityControlId":[{"Value":"IAM.6","Comparison":"EQUALS"}],"Region":[{"Value":"'"$identifiedregionline"'","Comparison":"EQUALS"}],"ComplianceAssociatedStandardsId": [{"Value": "'"$identifiedstandardsline"'","Comparison": "EQUALS"}]}' |jq '.Findings[]|.AwsAccountId' |wc -l)
		if [[ $gtemp < 2 ]]; then
			printf "Problem detected. Compliance framework is not reporting from region: $identifiedregionline $identifiedstandardsline\n"
			fi
	done
done


# PULL FAILING RESOURCES FOR PAGE 1

printf "\nCloudTrail.1 (AWS Audit Trail Logging) errors detected in the following accounts/regions:\n"
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "CloudTrail.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq '.Findings[]|.Resources[]|{Region, Id}| join (" ")'

printf "Config.1 (AWS Compliance Tracking) errors detected in the following accounts/regions:\n"
aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "Config.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],"Region":[{"Value":"'"$AWS_DEFAULT_REGION"'","Comparison":"EQUALS"}]}' |jq '.Findings[]|.Resources[]|{Region, Id}| join (" ")'

printf "GuardDuty.1 (AWS Threat Detection) errors detected in the following accounts/regions:\n"
aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "GuardDuty.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.Resources[]|{Region, Id}| join (" ")'


rm identified-regions-$accountid.txt
rm identified-standards-$accountid.txt
