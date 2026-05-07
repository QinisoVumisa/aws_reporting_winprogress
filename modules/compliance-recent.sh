#!/bin/bash

standards=(
    "AWS-Foundational-Security-Best-Practices"
    "CIS AWS Foundations Benchmark"
    "PCI-DSS"
)

printf "\n"
    printf "================================================================================\n"
    printf "LIST OF CONTROLS FAILING IN THE LAST 30 DAYS - CRITICAL AND HIGH ONLY.\n"
    printf "================================================================================\n\n"

for standard in "${standards[@]}"; do
    if [[ "$standard" != "CIS AWS Foundations Benchmark" ]]; then
        aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/'${standard}'","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"},{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}],"FirstObservedAt": [{"Start": "'$(date -v-180d -u +'%Y-%m-%dT%H:%M:%SZ')'","End": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'"}]}' |jq -r '(["Severity","'${standard:0:3}' Control","Resource ID"] | (., map(length*"-"))),(.Findings[] | [.Severity.Label, .Title, .Resources[].Id]) | @tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k1 -k2"}'|uniq| head -n 15
        printf "\n"
    else
        aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"},{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}],"FirstObservedAt": [{"Start": "'$(date -v-180d -u +'%Y-%m-%dT%H:%M:%SZ')'","End": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'"}]}' |jq -r '(["Severity","'${standard:0:3}' Control","Resource ID"] | (., map(length*"-"))),(.Findings[] | [.Severity.Label, .Title, .Resources[].Id]) | @tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k1 -k2"}'|uniq| head -n 15
        printf "\n"
    fi
done