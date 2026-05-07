#!/bin/bash


# printf "===\nChecking security monitoring tools enabled\n===\n"


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
printf "$numberofregions\n"

let totalaccountsregions=$accountsreporting*$numberofregions

#printf "Security Hub is monitoring security findings and events from the following AWS regions:\n"
aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "IAM.6","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.Resources[]|.Region' | sort| uniq | tee identified-regions-$accountid.txt

# PULL COMPLIANCE TABLE FOR PAGE 1

#printf "\n"
#printf "Number of regions failing CloudTrail.1 check (AWS Audit Trail):\t\t\t\t"
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "CloudTrail.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings|length'

#printf "Number of regions failing Config.1 check (AWS Configuration Tracking):\t\t\t\t"
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "Config.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings|length'


#printf "Number of regions failing GuardDuty.1 check (AWS Threat Detection):\t\t\t\t"
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "GuardDuty.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings|length'

printf "\n"

printf "The following AWS compliance standards have been detected in the environment:\n"
aws securityhub get-findings --output json  --filters '{"ComplianceSecurityControlId": [{"Value":"IAM.6","Comparison":"EQUALS"}],"RecordState":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}]}'| jq '.Findings[]|.Compliance.AssociatedStandards[].StandardsId' | sort | uniq |tee identified-standards-$accountid.txt

printf "\n"

#aws securityhub get-findings --filters '{"ProductFields": [{"Key": "RuleId","Value":"'$failingcontrol'","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print $0;next}{print $0| "sort -r"}' | sort | uniq

cat identified-standards-$accountid.txt | while read -r line; do
	failingcontrolline="$line"
	failingcontrol=$( echo "$failingcontrolline" | tr -d '"' )

	numberfailingcontrol=`aws securityhub get-findings --output json  --filters '{"ComplianceAssociatedStandardsId": [{"Value": "'$failingcontrol'","Comparison":"EQUALS"}],"ComplianceSecurityControlId": [{"Value":"IAM.6","Comparison":"EQUALS"}],"RecordState":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}]}'| jq '.Findings[]|.Resources[].Region' | sort | wc -l`	

	# Adding the two lines below because for some reason CIS and PCI aren't reporting IAM.6 even though it's part of the framework
	if [ $failingcontrol = "standards/pci-dss/v/3.2.1" ] ; then let "numberfailingcontrol = $numberfailingcontrol" ; fi	
	if [ $failingcontrol = "ruleset/cis-aws-foundations-benchmark/v/1.2.0" ]; then let "numberfailingcontrol = $numberfailingcontrol" ; fi


	printf "$failingcontrol:$numberfailingcontrol\n" >> failingcontroltablesource-$accountid.txt

done

printf "The compliance frameworks enabled below should equal the total number of accounts/regions to protect, which is $numberofregions\n\n"
cat failingcontroltablesource-$accountid.txt |  column -s: -t

rm failingcontroltablesource-$accountid.txt


#printf "\nNumber of AWS regions reporting AWS Foundational compliance: \t(should be $totalaccountsregions)\t "
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "CloudTrail.2","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq '.Findings[].AwsAccountId'| sort | uniq| wc -l

#printf "Number of AWS regions reporting CIS Foundations compliance: \t(should be $totalaccountsregions)\t "
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "RuleId","Value": "1.12","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings|length'

#printf "Number of AWS regions reporting PCI compliance: \t\t(should be $totalaccountsregions)\t "
#aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "PCI.CloudTrail.2","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[].AwsAccountId' |sort |uniq| wc -l

printf "\n"

# PULL FAILING RESOURCES FOR PAGE 1

printf "\nCloudTrail.1 (AWS Audit Trail Logging) errors detected in the following accounts/regions:\n"
aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "CloudTrail.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq '.Findings[]|.Resources[]|{Region, Id}| join (" ")'

printf "Config.1 (AWS Compliance Tracking) errors detected in the following accounts/regions:\n"
aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "Config.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq '.Findings[]|.Resources[]|{Region, Id}| join (" ")'

printf "GuardDuty.1 (AWS Threat Detection) errors detected in the following accounts/regions:\n"
aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "GuardDuty.1","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.Resources[]|{Region, Id}| join (" ")'

#printf "# -------------------------------------------------------------------------\nFetching seecurity monitoring status complete\n# -------------------------------------------------------------------------\n\n"


#Compare List of AWS/CIS/PCI regions against known list.
#create list of known accounts - this section should be updated to reference ControlTower accounts for more accurate results
aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "IAM.1","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.AwsAccountId' | sort| uniq > identified-accounts-$accountid.txt

printf "AWS Compliance Framework - Errors detected in the following accounts/regions:\n"

aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "IAM.1","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.AwsAccountId' | sort| uniq > aws-identified-accounts-$accountid.txt

aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "IAM.1","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.Resources[]|.Region' | sort| uniq > aws-identified-regions-$accountid.txt


diff identified-accounts-$accountid.txt aws-identified-accounts-$accountid.txt | grep \<
diff identified-regions-$accountid.txt aws-identified-regions-$accountid.txt | grep \<
rm aws-identified-regions-$accountid.txt
rm aws-identified-accounts-$accountid.txt

printf "CIS Compliance Framework - Errors detected in the following accounts/regions:\n"


aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "RuleId","Value": "1.12","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.AwsAccountId' | sort| uniq > cis-identified-accounts-$accountid.txt

aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "RuleId","Value": "1.12","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.Resources[]|.Region' | sort| uniq > cis-identified-regions-$accountid.txt


diff identified-accounts-$accountid.txt cis-identified-accounts-$accountid.txt | grep \<
diff identified-regions-$accountid.txt cis-identified-regions-$accountid.txt | grep \<
rm cis-identified-regions-$accountid.txt
rm cis-identified-accounts-$accountid.txt



printf "PCI Compliance Framework - Errors detected in the following accounts/regions:\n"



aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "PCI.CloudTrail.2","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.AwsAccountId' | sort| uniq > pci-identified-accounts-$accountid.txt

aws securityhub get-findings   --filters '{"ProductFields": [{"Key": "ControlId","Value": "PCI.CloudTrail.2","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'|jq '.Findings[]|.Resources[]|.Region' | sort| uniq > pci-identified-regions-$accountid.txt


diff identified-accounts-$accountid.txt pci-identified-accounts-$accountid.txt | grep \<
diff identified-regions-$accountid.txt pci-identified-regions-$accountid.txt | grep \<

printf "\n"

rm pci-identified-regions-$accountid.txt
rm pci-identified-accounts-$accountid.txt

rm identified-regions-$accountid.txt
rm identified-accounts-$accountid.txt
rm identified-standards-$accountid.txt

