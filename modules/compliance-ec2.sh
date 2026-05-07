export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10



printf "\n==============================================================================\n"
printf "EC2 COMPLIANCE SECTION\n"
printf "==============================================================================\n"

printf "\n======\nEC2 instances failing SSM.1 - EC2 should be managed by AWS Systems Manager\n======\n"

aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"SSM.1","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print$0;next}{print $0| "sort -r"}' | sort


printf "\n======\nEC2 instances failing SSM.3 - EC2 with SSM association errors\n======\n"

aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"SSM.3","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print$0;next}{print $0| "sort -r"}' | sort


printf "\n======\nEC2 instances failing SSM.2 - EC2 instances missing OS patching error. Missing or failed patches.\n======\n"

aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"SSM.2","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print$0;next}{print $0| "sort -r"}' | sort





