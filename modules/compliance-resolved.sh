#!/bin/bash

standards=(
    "AWS-Foundational-Security-Best-Practices"
    "CIS AWS Foundations Benchmark"
    "PCI-DSS"
)

printf "\n"
    printf "================================================================================\n"
    printf "LIST OF ISSUES RESOLVED IN THE LAST 30 DAYS - SCORE BOOSTERS.\n"
    printf "================================================================================\n\n"

for standard in "${standards[@]}"; do
    if [[ "$standard" != "CIS AWS Foundations Benchmark" ]]; then
        aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/'${standard}'","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"RESOLVED","Comparison":"EQUALS"}],"FirstObservedAt": [{"Start": "'$(date -v-60d -u +'%Y-%m-%dT%H:%M:%SZ')'","End": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'"}]}' |jq -r '(["Severity","'${standard:0:3}' Control"] | (., map(length*"-"))),(.Findings[] | [.Severity.Label, .Title]) | @tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k1 -k2"}'|uniq| head -n 15
        printf "\n"
    else
        aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"RESOLVED","Comparison":"EQUALS"}],"FirstObservedAt": [{"Start": "'$(date -v-60d -u +'%Y-%m-%dT%H:%M:%SZ')'","End": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'"}]}' |jq -r '(["Severity","'${standard:0:3}' Control"] | (., map(length*"-"))),(.Findings[] | [.Severity.Label, .Title]) | @tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k1 -k2"}'|uniq| head -n 15
        printf "\n"
    fi
done