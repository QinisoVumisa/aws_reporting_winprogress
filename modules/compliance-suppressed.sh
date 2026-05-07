#!/bin/bash

## ================Get Account Context ============================
#calleridentity=`aws sts get-caller-identity --output json 2> /dev/null` ## Get account id.
#if [[ ${#calleridentity} -gt 2 ]] ## Make sure we got a return value
#    then accountid=`jq -r '.Account' <<< $calleridentity 2> /dev/null`
#fi
#printf "# -------------------------------------------------------------------------\nFetching account context is complete\n# -------------------------------------------------------------------------\n"



printf "\n"
printf "================================================================================\n"
printf "APPENDIX: SUPPRESSED COMPLIANCE CHECKS\n-\n"
printf "For visibility and regular review. These are not being monitored for compliance\n"
printf "================================================================================\n\n"


# AWS SUPPRESSIONS
printf "===\nAWS Framework\n===\n"
aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'


# CIS SUPPRESSIONS
printf "\n"
printf "===\nCIS Framework\n===\n"

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'


#PCI SUPPRESSIONS
printf "\n"
printf "===\nPCI Framework\n===\n"

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.Severity.Label, .Title, .Resources[].Id])'

