#!/bin/bash

## ================Get Account Context ============================
#calleridentity=`aws sts get-caller-identity --output json 2> /dev/null` ## Get account id.
#if [[ ${#calleridentity} -gt 2 ]] ## Make sure we got a return value
#    then accountid=`jq -r '.Account' <<< $calleridentity 2> /dev/null`
#fi
#printf "# -------------------------------------------------------------------------\nFetching account context is complete\n# -------------------------------------------------------------------------\n"

# First check framework status (silent - for internal use only)
source ./modules/compliance-framework-status.sh >/dev/null 2>&1

printf "\n"
printf "================================================================================\n"
printf "LIST OF FAILING CONTROLS - CRITICAL AND HIGH ONLY.\n"
printf "================================================================================\n"

printf "\nSeverity  AWS Control\n"
printf -- "--------  -----------\n"
aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}'|uniq| head -n 15

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}'|sort |uniq

printf "\nSeverity  CIS Control\n"
printf -- "--------  -----------\n"
aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}'|uniq| head -n 15

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}'|sort |uniq

printf "\nSeverity  PCI Control\n"
printf -- "--------  -----------\n"
aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}'|uniq| head -n 15

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}'| sort |uniq

printf "\n"

