#!/bin/bash

## ================Get Account Context ============================
calleridentity=`aws sts get-caller-identity --output json 2> /dev/null` ## Get account id.
if [[ ${#calleridentity} -gt 2 ]] ## Make sure we got a return value
    then accountid=`jq -r '.Account' <<< $calleridentity 2> /dev/null`
fi
#printf "# -------------------------------------------------------------------------\nFetching account context is complete\n# -------------------------------------------------------------------------\n"

export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10

# Load framework status
source ./modules/compliance-framework-status.sh



# this ignore list is for the controls which are covered in the "top priority" section of the report

IGNORE_CONTROLS_REGEX='(SSM.1|SSM.2|SSM.3|EC2.19|S3.8|EC2.7|IAM.5)'


printf "\n================================================================================\n"
printf "COMPLIANCE FAILURES - RESOURCE DETAIL SECTION - TOP FIVE\n-"
printf "\nPlease remediate the following, if the risk is accepted, then let us know so that we can suppress the check\n"
printf "================================================================================"


printf "\n=============\n"
printf "AWS Framework"
printf "\n=============\n"

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["AWS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq > failingawschecks-$accountid

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["AWS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingawschecks-$accountid

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["AWS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingawschecks-$accountid

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["AWS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingawschecks-$accountid

sed -i '' '/ControlID/d' ./failingawschecks-$accountid
sed -i '' '/-----/d' ./failingawschecks-$accountid

head -5 failingawschecks-$accountid | while read -r line; do
    if ! [[ $line =~ $IGNORE_CONTROLS_REGEX ]]; then	
failingcontrolline="$line"
failingcontrol=$( echo "$failingcontrolline" |cut -d ' ' -f 1 )    
failingcontroltitle=$( echo "$failingcontrolline" | awk '{$1=""; print $0}' | sed 's/\s/\t\t/2;P;D')
printf "\n\n$failingcontroltitle\n===\n"
aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"'$failingcontrol'","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print$0;next}{print $0| "sort -r"}' | sort | uniq
	fi

done  

rm ./failingawschecks-$accountid



printf "\n=============\n"
printf "CIS AWS Foundations Benchmark v3.0.0"
printf "\n=============\n"

# Check if CIS v3.0.0 is enabled
if [[ "$CIS_AWS_Foundations_v3_0_0_ENABLED" == "true" ]] || [[ "$CIS_AWS_Foundations_v3_0_0_ENABLED" == "partial" ]]; then
    aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/3.0.0","Comparison": "PREFIX"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["CIS v3.0.0 ControlID","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.RuleId // .GeneratorId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq > failingcis3checks-$accountid

    aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/3.0.0","Comparison": "PREFIX"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.ProductFields.RuleId // .GeneratorId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingcis3checks-$accountid

    sed -i '' '/ControlID/d' ./failingcis3checks-$accountid
    sed -i '' '/-----/d' ./failingcis3checks-$accountid

    if [[ -s failingcis3checks-$accountid ]]; then
        head -5 failingcis3checks-$accountid | while read -r line; do
            failingcontrolline="$line"
            failingcontrol=$( echo "$failingcontrolline" |cut -d ' ' -f 1 )
            failingcontroltitle=$( echo "$failingcontrolline" | awk '{$1=""; print $0}' | sed 's/\s/\t\t/2;P;D')
            printf "\n\n$failingcontroltitle\n===\n"
            aws securityhub get-findings --filters '{"GeneratorId": [{"Value": "'$failingcontrol'","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print$0;next}{print $0| "sort -r"}' | sort | uniq
        done
    else
        printf "\nNo CIS AWS Foundations v3.0.0 failing controls found\n"
    fi
    rm -f ./failingcis3checks-$accountid
else
    printf "\n⚠️  CIS AWS Foundations Benchmark v3.0.0 is not enabled\n"
fi

printf "\n=============\n"
printf "CIS AWS Foundations Benchmark v1.4.0"
printf "\n=============\n"

# Check if CIS v1.4.0 is enabled
if [[ "$CIS_AWS_Foundations_v1_4_0_ENABLED" == "true" ]] || [[ "$CIS_AWS_Foundations_v1_4_0_ENABLED" == "partial" ]]; then
    aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/1.4.0","Comparison": "PREFIX"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["CIS v1.4.0 ControlID","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.RuleId // .GeneratorId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq > failingcis1checks-$accountid

    aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/1.4.0","Comparison": "PREFIX"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.ProductFields.RuleId // .GeneratorId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingcis1checks-$accountid

    sed -i '' '/ControlID/d' ./failingcis1checks-$accountid
    sed -i '' '/-----/d' ./failingcis1checks-$accountid

    if [[ -s failingcis1checks-$accountid ]]; then
        head -5 failingcis1checks-$accountid | while read -r line; do
            failingcontrolline="$line"
            failingcontrol=$( echo "$failingcontrolline" |cut -d ' ' -f 1 )
            failingcontroltitle=$( echo "$failingcontrolline" | awk '{$1=""; print $0}' | sed 's/\s/\t\t/2;P;D')
            printf "\n\n$failingcontroltitle\n===\n"
            aws securityhub get-findings --filters '{"GeneratorId": [{"Value": "'$failingcontrol'","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print$0;next}{print $0| "sort -r"}' | sort | uniq
        done
    else
        printf "\nNo CIS AWS Foundations v1.4.0 failing controls found\n"
    fi
    rm -f ./failingcis1checks-$accountid
else
    printf "\n⚠️  CIS AWS Foundations Benchmark v1.4.0 is not enabled\n"
fi

printf "\n=============\n"
printf "Generic CIS Framework (Fallback)"
printf "\n=============\n"

aws securityhub get-findings --filters '{"ProductFields": [{"Key" : "StandardsGuideArn", "Value": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0", "Comparison" : "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["CIS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.RuleId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq > failingcischecks-$accountid

aws securityhub get-findings --filters '{"ProductFields": [{"Key" : "StandardsGuideArn", "Value": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0", "Comparison" : "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["CIS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.RuleId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingcischecks-$accountid

aws securityhub get-findings --filters '{"ProductFields": [{"Key" : "StandardsGuideArn", "Value": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0", "Comparison" : "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["CIS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.RuleId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingcischecks-$accountid

aws securityhub get-findings --filters '{"ProductFields": [{"Key" : "StandardsGuideArn", "Value": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0", "Comparison" : "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["CIS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.RuleId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingcischecks-$accountid


sed -i '' '/ControlID/d' ./failingcischecks-$accountid
sed -i '' '/-----/d' ./failingcischecks-$accountid

head -5 failingcischecks-$accountid | while read -r line; do
    failingcontrolline="$line"
    failingcontrol=$( echo "$failingcontrolline" |cut -d ' ' -f 1 )
    failingcontroltitle=$( echo "$failingcontrolline" | awk '{$1=""; print $0}' | sed 's/\s/\t\t/2;P;D')
    printf "\n\n$failingcontroltitle\n===\n"

aws securityhub get-findings --filters '{"ProductFields": [{"Key": "RuleId","Value":"'$failingcontrol'","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print $0;next}{print $0| "sort -r"}' | sort | uniq
done

rm ./failingcischecks-$accountid


printf "\n=============\n"
printf "PCI DSS v4.0.1"
printf "\n=============\n"

# Check if PCI DSS v4.0.1 is enabled
if [[ "$PCI_DSS_v4_0_1_ENABLED" == "true" ]] || [[ "$PCI_DSS_v4_0_1_ENABLED" == "partial" ]]; then
    aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "pci-dss/v/4.0.1","Comparison": "PREFIX"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["PCI DSS v4.0.1 ControlID","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq > failingpci4checks-$accountid

    aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "pci-dss/v/4.0.1","Comparison": "PREFIX"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingpci4checks-$accountid

    sed -i '' '/ControlID/d' ./failingpci4checks-$accountid
    sed -i '' '/-----/d' ./failingpci4checks-$accountid

    if [[ -s failingpci4checks-$accountid ]]; then
        head -5 failingpci4checks-$accountid | while read -r line; do
            failingcontrolline="$line"
            failingcontrol=$( echo "$failingcontrolline" |cut -d ' ' -f 1 )
            failingcontroltitle=$( echo "$failingcontrolline" | awk '{$1=""; print $0}' | sed 's/\s/\t\t/2;P;D')
            printf "\n\n$failingcontroltitle\n===\n"
            aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"'$failingcontrol'","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "pci-dss/v/4.0.1","Comparison": "PREFIX"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print$0;next}{print $0| "sort -r"}' | sort | uniq
        done
    else
        printf "\nNo PCI DSS v4.0.1 failing controls found\n"
    fi
    rm -f ./failingpci4checks-$accountid
else
    printf "\n⚠️  PCI DSS v4.0.1 is not enabled\n"
fi

printf "\n=============\n"
printf "Generic PCI Framework (Fallback)"
printf "\n=============\n"

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["AWS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq > failingpcichecks-$accountid

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["AWS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingpcichecks-$accountid

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["AWS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingpcichecks-$accountid

aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}]}' |jq -r '(["AWS ControlID   ","Severity","Description"] | (., map(length*"-"))),(.Findings[]|[.ProductFields.ControlId,.Severity.Label,.Title])|@tsv'| column -ts $'\t'| awk 'NR<3{print $0;next}{print $0| "sort -k2 -k1"}' |sort |uniq >> failingpcichecks-$accountid


sed -i '' '/ControlID/d' ./failingpcichecks-$accountid
sed -i '' '/-----/d' ./failingpcichecks-$accountid

head -5 failingpcichecks-$accountid | while read -r line; do
    failingcontrolline="$line"
    failingcontrol=$( echo "$failingcontrolline" |cut -d ' ' -f 1 )
    failingcontroltitle=$( echo "$failingcontrolline" | awk '{$1=""; print $0}' | sed 's/\s/\t\t/2;P;D')
    printf "\n\n$failingcontroltitle\n===\n"
aws securityhub get-findings --filters '{"ProductFields": [{"Key": "ControlId","Value":"'$failingcontrol'","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "INFORMATIONAL","Comparison": "NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' |jq -r '(.Findings[]|[.AwsAccountId,.Resources[].Id, .Resources[].Details.AwsEc2SecurityGroup.GroupName // "-"]) | @tsv' | column -ts $'\t' | awk 'NR<3{print $0;next}{print $0| "sort -r"}' | sort | uniq
done

rm ./failingpcichecks-$accountid




