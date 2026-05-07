#!/bin/bash

## ================Get Account Context ============================
calleridentity=`aws sts get-caller-identity --output json 2> /dev/null` ## Get account id.
if [[ ${#calleridentity} -gt 2 ]] ## Make sure we got a return value
    then accountid=`jq -r '.Account' <<< $calleridentity 2> /dev/null`
fi

thismonthnumber=$(date +%m)
today=$(date +"%Y-%m-%d")
day=$(date +"%d")
dateyesterday=$(date -v-1d '+%Y-%m-%d')

export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10

#write customer name to the DynamoDB score-tracking table
if [[ "$custname" ]]; then
aws --region eu-west-1 --profile instance-profile dynamodb update-item --table-name mcs-customer-sechub-scores --key "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" --update-expression "SET ACustomerName = :NewCustomerName" --expression-attribute-values "{\":NewCustomerName\" : {\"S\":\"$custname\"}}"
fi

printf "\n\n\n"
printf "\n==============================================================================\n"
printf "INFRASTRUCTURE COMPLIANCE SECTION\n-\n"
printf "Compliance remediation prevents attackers from accessing the environment, and limits their ability to cause damage\n"
printf "==============================================================================\n\n"

# Load framework status
source ./modules/compliance-framework-status.sh >/dev/null 2>&1

# Get compliance findings for score calculations
awscontrolsresult=`aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'`

ciscontrolsresult=`aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"ProductFields":[{"Key":"StandardsGuideArn","Value":"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'`

pcicontrolsresult=`aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/pci-dss/v/3.2.1","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'`

# Calculate main framework scores
totalnumberawscontrolsreportingstatus=`echo $awscontrolsresult | jq ".Findings[].GeneratorId" | sort | uniq | wc -l`
totalnumberawscontrolsfailed=`echo $awscontrolsresult | jq '.Findings[] | select(.Compliance.Status == "FAILED") | .GeneratorId' | sort | uniq | wc -l`
totalnumberawscontrolsnotpassed=`echo $awscontrolsresult | jq '.Findings[] | select(.Compliance.Status != "PASSED") | .GeneratorId' | sort | uniq | wc -l`

totalnumberciscontrolsreportingstatus=`echo $ciscontrolsresult | jq ".Findings[].GeneratorId" | sort | uniq | wc -l`
totalnumberciscontrolsfailed=`echo $ciscontrolsresult | jq '.Findings[] | select(.Compliance.Status == "FAILED") | .GeneratorId' | sort | uniq | wc -l`
totalnumberciscontrolsnotpassed=`echo $ciscontrolsresult | jq '.Findings[] | select(.Compliance.Status != "PASSED") | .GeneratorId' | sort | uniq | wc -l`

totalnumberpcicontrolsreportingstatus=`echo $pcicontrolsresult | jq ".Findings[].GeneratorId" | sort | uniq | wc -l`
totalnumberpcicontrolsfailed=`echo $pcicontrolsresult | jq '.Findings[] | select(.Compliance.Status == "FAILED") | .GeneratorId' | sort | uniq | wc -l`
totalnumberpcicontrolsnotpassed=`echo $pcicontrolsresult | jq '.Findings[] | select(.Compliance.Status != "PASSED") | .GeneratorId' | sort | uniq | wc -l`

# Calculate passed controls and scores
awspasses=$((totalnumberawscontrolsreportingstatus-totalnumberawscontrolsnotpassed))
if [[ $totalnumberawscontrolsreportingstatus -lt 1 ]]; then 
    printf "AWS Control Enumeration Issue Detected\n"
    awsfoundationalscore="N/A"
else
    awsfoundationalscore=$(awk "BEGIN { pc=100*${awspasses}/${totalnumberawscontrolsreportingstatus}; i=int(pc); print (pc-i<0.5)?i:i+1 }")
fi

cispasses=$((totalnumberciscontrolsreportingstatus-totalnumberciscontrolsnotpassed))
if [[ $totalnumberciscontrolsreportingstatus -lt 1 ]]; then 
    printf "CIS Control Enumeration Issue Detected\n"
    cisfoundationsscore="N/A"
else
    cisfoundationsscore=$(awk "BEGIN { pc=100*${cispasses}/${totalnumberciscontrolsreportingstatus}; i=int(pc); print (pc-i<0.5)?i:i+1 }")
fi

pcipasses=$((totalnumberpcicontrolsreportingstatus-totalnumberpcicontrolsnotpassed))
if [[ $totalnumberpcicontrolsreportingstatus -lt 1 ]]; then 
    printf "PCI Control Enumeration Issue Detected\n"
    pciscore="N/A"
else
    pciscore=$(awk "BEGIN { pc=100*${pcipasses}/${totalnumberpcicontrolsreportingstatus}; i=int(pc); print (pc-i<0.5)?i:i+1 }")
fi

# Enhanced version-specific framework reporting
# CIS v1.4.0 Framework
if [[ "$CIS_AWS_Foundations_v1_4_0_ENABLED" == "true" ]] || [[ "$CIS_AWS_Foundations_v1_4_0_ENABLED" == "partial" ]]; then
    cis14controlsresult=`aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/1.4.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'`
    
    totalnumbercis14controlsreportingstatus=`echo $cis14controlsresult | jq ".Findings[].GeneratorId" | sort | uniq | wc -l`
    totalnumbercis14controlsfailed=`echo $cis14controlsresult | jq '.Findings[] | select(.Compliance.Status == "FAILED") | .GeneratorId' | sort | uniq | wc -l`
    totalnumbercis14controlsnotpassed=`echo $cis14controlsresult | jq '.Findings[] | select(.Compliance.Status != "PASSED") | .GeneratorId' | sort | uniq | wc -l`
    cis14foundationspasses=$((totalnumbercis14controlsreportingstatus-totalnumbercis14controlsnotpassed))
    
    if [[ $totalnumbercis14controlsreportingstatus -lt 1 ]]; then 
        cis14enumissue="CIS v1.4.0 Control Enumeration Issue Detected"
        cis14foundationsscore="N/A"
    else
        cis14foundationsscore=$(awk "BEGIN { pc=100*${cis14foundationspasses}/${totalnumbercis14controlsreportingstatus}; i=int(pc); print (pc-i<0.5)?i:i+1 }")
        cis14enumissue=""
    fi
else
    totalnumbercis14controlsreportingstatus=0
    totalnumbercis14controlsfailed=0
    cis14foundationspasses=0
    cis14foundationsscore="N/A"
    cis14enumissue=""
fi

# CIS v3.0.0 Framework
if [[ "$CIS_AWS_Foundations_v3_0_0_ENABLED" == "true" ]] || [[ "$CIS_AWS_Foundations_v3_0_0_ENABLED" == "partial" ]]; then
    cis30controlsresult=`aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/3.0.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'`
    
    totalnumbercis30controlsreportingstatus=`echo $cis30controlsresult | jq ".Findings[].GeneratorId" | sort | uniq | wc -l`
    totalnumbercis30controlsfailed=`echo $cis30controlsresult | jq '.Findings[] | select(.Compliance.Status == "FAILED") | .GeneratorId' | sort | uniq | wc -l`
    totalnumbercis30controlsnotpassed=`echo $cis30controlsresult | jq '.Findings[] | select(.Compliance.Status != "PASSED") | .GeneratorId' | sort | uniq | wc -l`
    cis30foundationspasses=$((totalnumbercis30controlsreportingstatus-totalnumbercis30controlsnotpassed))
    
    if [[ $totalnumbercis30controlsreportingstatus -lt 1 ]]; then 
        cis30enumissue="CIS v3.0.0 Control Enumeration Issue Detected"
        cis30foundationsscore="N/A"
    else
        cis30foundationsscore=$(awk "BEGIN { pc=100*${cis30foundationspasses}/${totalnumbercis30controlsreportingstatus}; i=int(pc); print (pc-i<0.5)?i:i+1 }")
        cis30enumissue=""
    fi
else
    totalnumbercis30controlsreportingstatus=0
    totalnumbercis30controlsfailed=0
    cis30foundationspasses=0
    cis30foundationsscore="N/A"
    cis30enumissue=""
fi

# PCI v4.0.1 Framework
if [[ "$PCI_DSS_v4_0_1_ENABLED" == "true" ]] || [[ "$PCI_DSS_v4_0_1_ENABLED" == "partial" ]]; then
    pci4controlsresult=`aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "pci-dss/v/4.0.1","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'`
    
    totalnumberpci4controlsreportingstatus=`echo $pci4controlsresult | jq ".Findings[].GeneratorId" | sort | uniq | wc -l`
    totalnumberpci4controlsfailed=`echo $pci4controlsresult | jq '.Findings[] | select(.Compliance.Status == "FAILED") | .GeneratorId' | sort | uniq | wc -l`
    totalnumberpci4controlsnotpassed=`echo $pci4controlsresult | jq '.Findings[] | select(.Compliance.Status != "PASSED") | .GeneratorId' | sort | uniq | wc -l`
    pci4passes=$((totalnumberpci4controlsreportingstatus-totalnumberpci4controlsnotpassed))
    
    if [[ $totalnumberpci4controlsreportingstatus -lt 1 ]]; then 
        pci4enumissue="PCI v4.0.1 Control Enumeration Issue Detected"
        pci4score="N/A"
    else
        pci4score=$(awk "BEGIN { pc=100*${pci4passes}/${totalnumberpci4controlsreportingstatus}; i=int(pc); print (pc-i<0.5)?i:i+1 }")
        pci4enumissue=""
    fi
else
    totalnumberpci4controlsreportingstatus=0
    totalnumberpci4controlsfailed=0
    pci4passes=0
    pci4score="N/A"
    pci4enumissue=""
fi

# Display current scores
printf "%-39s: %-12s %-39s: %-12s %-39s: %s\n" "AWS Controls - Reporting Status" "$totalnumberawscontrolsreportingstatus" "CIS Controls - Reporting Status" "$totalnumberciscontrolsreportingstatus" "PCI Controls - Reporting Status" "$totalnumberpcicontrolsreportingstatus"
printf "%-39s: %-12s %-39s: %-12s %-39s: %s\n" "AWS Controls - Failed" "$totalnumberawscontrolsfailed" "CIS Controls - Failed" "$totalnumberciscontrolsfailed" "PCI Controls - Failed" "$totalnumberpcicontrolsfailed"
printf "%-39s: %-12s %-39s: %-12s %-39s: %s\n" "AWS Controls - Pass" "$awspasses" "CIS Controls - Pass" "$cispasses" "PCI Controls - Pass" "$pcipasses"
printf "%-39s: %-12s %-39s: %-12s %-39s: %s\n" "AWS Foundations Score" "$awsfoundationalscore%" "CIS Foundations Score" "$cisfoundationsscore%" "PCI Score" "$pciscore%"

printf "\n"

printf "%-39s: %-12s %-39s: %-12s %-39s: %s\n" "CIS v1.4 Controls - Reporting Status" "$totalnumbercis14controlsreportingstatus" "CIS v3.0  Controls - Reporting Status" "$totalnumbercis30controlsreportingstatus" "PCI v4.0.1 Controls - Reporting Status" "$totalnumberpci4controlsreportingstatus"
printf "%-39s: %-12s %-39s: %-12s %-39s: %s\n" "CIS v1.4 Controls - Failed" "$totalnumbercis14controlsfailed" "CIS v3.0  Controls - Failed" "$totalnumbercis30controlsfailed" "PCI v4.0.1 Controls - Failed" "$totalnumberpci4controlsfailed"
printf "%-39s: %-12s %-39s: %-12s %-39s: %s\n" "CIS v1.4 Controls - Pass" "$cis14foundationspasses" "CIS v3.0  Controls - Passed" "$cis30foundationspasses" "PCI v4.0.1 Controls - Pass" "$pci4passes"

if [[ -n "$cis14enumissue" ]]; then printf "$cis14enumissue\n"; fi
if [[ -n "$cis30enumissue" ]]; then printf "$cis30enumissue\n"; fi
if [[ -n "$pci4enumissue" ]]; then printf "$pci4enumissue\n"; fi

printf "%-39s: %-12s %-39s: %-12s %-39s: %s\n" "CIS v1.4 Foundations Score" "$cis14foundationsscore%" "CIS v3.0 Foundations Score" "$cis30foundationsscore%" "PCI v4.0.1 Score" "$pci4score%"

#write the latest compliance scores to DynamoDB - ONLY IF THIS IS RUN ON THE 1st to the 5th of the month!
day2=$(date +"%Oe"| sed 's/ //')
if [[ day2 -le 5 ]]; then
    aws --region eu-west-1 --profile instance-profile dynamodb update-item --table-name mcs-customer-sechub-scores --key "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" --update-expression "SET AWS$thismonthnumber = :NewScore" --expression-attribute-values "{\":NewScore\" : {\"N\":\"$awsfoundationalscore\"}}" 2>/dev/null
    aws --region eu-west-1 --profile instance-profile dynamodb update-item --table-name mcs-customer-sechub-scores --key "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" --update-expression "SET CIS$thismonthnumber = :NewScore" --expression-attribute-values "{\":NewScore\" : {\"N\":\"$cisfoundationsscore\"}}" 2>/dev/null
    aws --region eu-west-1 --profile instance-profile dynamodb update-item --table-name mcs-customer-sechub-scores --key "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" --update-expression "SET PCI$thismonthnumber = :NewScore" --expression-attribute-values "{\":NewScore\" : {\"N\":\"$pciscore\"}}" 2>/dev/null

    # Update new framework scores
    if [[ -n "$cis14foundationsscore" ]] && [[ "$cis14foundationsscore" != "N/A" ]]; then
        aws --region eu-west-1 --profile instance-profile dynamodb update-item --table-name mcs-customer-sechub-scores --key "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" --update-expression "SET CIS14$thismonthnumber = :NewScore" --expression-attribute-values "{\":NewScore\" : {\"N\":\"$cis14foundationsscore\"}}" 2>/dev/null
    fi

    if [[ -n "$cis30foundationsscore" ]] && [[ "$cis30foundationsscore" != "N/A" ]]; then
        aws --region eu-west-1 --profile instance-profile dynamodb update-item --table-name mcs-customer-sechub-scores --key "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" --update-expression "SET CIS30$thismonthnumber = :NewScore" --expression-attribute-values "{\":NewScore\" : {\"N\":\"$cis30foundationsscore\"}}" 2>/dev/null
    fi

    if [[ -n "$pci4score" ]] && [[ "$pci4score" != "N/A" ]]; then
        aws --region eu-west-1 --profile instance-profile dynamodb update-item --table-name mcs-customer-sechub-scores --key "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" --update-expression "SET PCI4$thismonthnumber = :NewScore" --expression-attribute-values "{\":NewScore\" : {\"N\":\"$pci4score\"}}" 2>/dev/null
    fi
fi

#   Write the previous scores matrix to screen - retrieving from DynamoDB
printf "\n\nHistorical scores per framework as recorded in monthly report. (NULL = Score not yet saved in DB)\n"
printf "===========================================================================\n"
printf "Month              "

loopcounter=5
while [ $loopcounter -ge 0 ]
do
        echo -n `date -v-${loopcounter}m +%b`
        echo -ne "\t"
        ((loopcounter--))
done

printf "\n\n"

# AWS LOOP - PULL HISTORICAL SCORES
printf "AWS Scores:\t"

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d' $scoremonthcounter)
    fi
    
    # Try to get historical score from DynamoDB first (with error handling and fallback)
    if [[ $scoremonthcounter -le 9 ]]; then
        month_key=$(printf '%02d' $scoremonthcounter)
    else
        month_key=$scoremonthcounter
    fi
    
    # First attempt: Try with instance-profile
    historical_score=$(aws --region eu-west-1 --profile instance-profile dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.AWS'$month_key'|.N)' 2>/dev/null)
    
    # Second attempt: If profile fails, try without profile (using default credentials)
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score=$(aws --region eu-west-1 dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.AWS'$month_key'|.N)' 2>/dev/null)
    fi
    
    # Third attempt: If DynamoDB completely fails, set as N/A
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score="N/A"
    fi
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "\t"
    ((loopcounter--))
done

printf "\n"

# CIS LOOP - PULL HISTORICAL SCORES
printf "CIS Scores:\t"

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d' $scoremonthcounter)
    fi

    # Try to get historical CIS score from DynamoDB first (with error handling and fallback)
    if [[ $scoremonthcounter -le 9 ]]; then
        month_key=$(printf '%02d' $scoremonthcounter)
    else
        month_key=$scoremonthcounter
    fi
    
    # First attempt: Try with instance-profile
    historical_score=$(aws --region eu-west-1 --profile instance-profile dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.CIS'$month_key'|.N)' 2>/dev/null)
    
    # Second attempt: If profile fails, try without profile (using default credentials)
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score=$(aws --region eu-west-1 dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.CIS'$month_key'|.N)' 2>/dev/null)
    fi
    
    # Third attempt: If DynamoDB completely fails, set as N/A
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score="N/A"
    fi
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "\t"
    ((loopcounter--))
done

printf "\n"

# CIS v1.4 LOOP - PULL HISTORICAL SCORES
printf "CIS v1.4 Scores:\t"

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d' $scoremonthcounter)
    fi

    # Try to get historical CIS v1.4 score from DynamoDB first
    if [[ $scoremonthcounter -le 9 ]]; then
        month_key=$(printf '%02d' $scoremonthcounter)
    else
        month_key=$scoremonthcounter
    fi
    
    # First attempt: Try with instance-profile
    historical_score=$(aws --region eu-west-1 --profile instance-profile dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.CIS14'$month_key'|.N)' 2>/dev/null)
    
    # Second attempt: If profile fails, try without profile
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score=$(aws --region eu-west-1 dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.CIS14'$month_key'|.N)' 2>/dev/null)
    fi
    
    # Third attempt: If DynamoDB completely fails, set as N/A
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score="N/A"
    fi
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "\t"
    ((loopcounter--))
done

printf "\n"

# CIS v3.0 LOOP - PULL HISTORICAL SCORES
printf "CIS v3.0 Scores:\t"

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d' $scoremonthcounter)
    fi

    # For CIS v3.0, always set as N/A since it's relatively new
    historical_score="N/A"
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "\t"
    ((loopcounter--))
done

printf "\n"

# PCI LOOP - PULL HISTORICAL SCORES
printf "PCI Scores:\t"

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d' $scoremonthcounter)
    fi

    # Try to get historical PCI score from DynamoDB
    if [[ $scoremonthcounter -le 9 ]]; then
        month_key=$(printf '%02d' $scoremonthcounter)
    else
        month_key=$scoremonthcounter
    fi
    
    # First attempt: Try with instance-profile
    historical_score=$(aws --region eu-west-1 --profile instance-profile dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.PCI'$month_key'|.N)' 2>/dev/null)
    
    # Second attempt: If profile fails, try without profile
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score=$(aws --region eu-west-1 dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.PCI'$month_key'|.N)' 2>/dev/null)
    fi
    
    # Third attempt: If DynamoDB completely fails, set as N/A
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score="N/A"
    fi
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "\t"
    ((loopcounter--))
done

printf "\n"

# PCI v4 LOOP - PULL HISTORICAL SCORES
printf "PCI v4 Scores:\t"

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d' $scoremonthcounter)
    fi

    # Try to get historical PCI v4 score from DynamoDB
    if [[ $scoremonthcounter -le 9 ]]; then
        month_key=$(printf '%02d' $scoremonthcounter)
    else
        month_key=$scoremonthcounter
    fi
    
    # First attempt: Try with instance-profile
    historical_score=$(aws --region eu-west-1 --profile instance-profile dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.PCI4'$month_key'|.N)' 2>/dev/null)
    
    # Second attempt: If profile fails, try without profile
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score=$(aws --region eu-west-1 dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.PCI4'$month_key'|.N)' 2>/dev/null)
    fi
    
    # Third attempt: If DynamoDB completely fails, set as N/A
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]] || [[ "$historical_score" == "" ]]; then
        historical_score="N/A"
    fi
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "\t"
    ((loopcounter--))
done

printf "\n"
printf "  \n"
