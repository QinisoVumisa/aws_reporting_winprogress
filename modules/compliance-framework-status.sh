#!/bin/bash

## ================Framework Status Checker============================
# This module checks if specific compliance frameworks are enabled and reports their status
# Target frameworks: CIS AWS Foundations v3.0.0, PCI DSS v4.0.1, CIS AWS Foundations v1.4.0

# Function to calculate real-time score from Security Hub
get_realtime_score() {
    local framework=$1
    local today=$(date +"%Y-%m-%d")
    local dateyesterday=$(date -v-1d '+%Y-%m-%d')
    local controlsresult
    local score
    
    case $framework in
        AWS)
            controlsresult=$(aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' 2>/dev/null)
            ;;
        CIS)
            controlsresult=$(aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"ProductFields":[{"Key":"StandardsGuideArn","Value":"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' 2>/dev/null)
            ;;
        CIS14)
            controlsresult=$(aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/1.4.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' 2>/dev/null)
            ;;
        CIS30)
            controlsresult=$(aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/3.0.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' 2>/dev/null)
            ;;
        PCI)
            controlsresult=$(aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/pci-dss/v/3.2.1","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' 2>/dev/null)
            ;;
        PCI4)
            controlsresult=$(aws securityhub get-findings --filters '{"UpdatedAt": [{"Start":"'"$dateyesterday"'","End":"'"$today"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "pci-dss/v/4.0.1","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' 2>/dev/null)
            ;;
        *)
            echo "N/A"
            return
            ;;
    esac
    
    if [[ -z "$controlsresult" ]] || [[ "$controlsresult" == "null" ]]; then
        echo "N/A"
        return
    fi
    
    # Calculate score
    local total=$(echo $controlsresult | jq ".Findings[].GeneratorId" 2>/dev/null | sort | uniq | wc -l)
    local notpassed=$(echo $controlsresult | jq '.Findings[] | select(.Compliance.Status != "PASSED") | .GeneratorId' 2>/dev/null | sort | uniq | wc -l)
    
    if [[ $total -lt 1 ]]; then
        echo "N/A"
        return
    fi
    
    local passes=$((total - notpassed))
    score=$(awk "BEGIN { pc=100*${passes}/${total}; i=int(pc); print (pc-i<0.5)?i:i+1 }")
    echo "$score"
}

# Function to fetch score from DynamoDB
get_historical_score() {
    local framework=$1
    local month_key=$2
    local current_month=$(date +%m)
    local historical_score
    
    # First attempt: Try with instance-profile
    historical_score=$(aws --region eu-west-1 --profile instance-profile dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.'$framework''$month_key'|.N)' 2>/dev/null)
    
    # Second attempt: If profile fails, try without profile (using default credentials)
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]]; then
        historical_score=$(aws --region eu-west-1 dynamodb scan --table-name mcs-customer-sechub-scores --filter-expression "SecHubAccountId = :SHACCID" --expression-attribute-values '{":SHACCID":{"N":"'$accountid'"}}' 2>/dev/null | jq -r '(.Items[]|.'$framework''$month_key'|.N)' 2>/dev/null)
    fi
    
    # Third attempt: If DynamoDB has no data AND this is the current month, fetch real-time from Security Hub
    if [[ "$historical_score" == "null" ]] || [[ -z "$historical_score" ]]; then
        if [[ "$month_key" == "$current_month" ]]; then
            historical_score=$(get_realtime_score "$framework")
        else
            historical_score="N/A"
        fi
    fi
    
    echo "$historical_score"
}

# Function to generate historical scores table
generate_historical_scores() {
    # Get account ID if not already set
    if [[ -z "$accountid" ]]; then
        calleridentity=$(aws sts get-caller-identity --output json 2>/dev/null)
        if [[ ${#calleridentity} -gt 2 ]]; then
            accountid=$(jq -r '.Account' <<< $calleridentity 2>/dev/null)
        fi
    fi
    
    # Get current month number
    thismonthnumber=$(date +%m)
    
    # Calculate starting month (5 months ago)
    scoremonthcounter=$(echo $thismonthnumber | sed 's/^0*//')
    scoremonthcounter=$((scoremonthcounter - 5))
    if [[ $scoremonthcounter -lt 1 ]]; then
        scoremonthcounter=$((scoremonthcounter + 12))
    fi
    
    # Build month headers and collect scores for each framework
    declare -a months=()
    declare -a aws_scores=()
    declare -a cis_scores=()
    declare -a cis14_scores=()
    declare -a cis30_scores=()
    declare -a pci_scores=()
    declare -a pci4_scores=()
    
    current_month=$scoremonthcounter
    for i in {1..6}; do
        # Format month for display
        if [[ $current_month -ge 1 ]] && [[ $current_month -le 12 ]]; then
            month_display=$(date -v${current_month}m +%b 2>/dev/null || date -j -f "%m" "$current_month" +%b 2>/dev/null)
        else
            month_display="N/A"
        fi
        months+=("$month_display")
        
        # Format month key for DynamoDB (2 digits)
        month_key=$(printf '%02d' $current_month)
        
        # Fetch scores for each framework
        aws_scores+=("$(get_historical_score 'AWS' $month_key)%")
        cis_scores+=("$(get_historical_score 'CIS' $month_key)%")
        cis14_scores+=("$(get_historical_score 'CIS14' $month_key)%")
        cis30_scores+=("$(get_historical_score 'CIS30' $month_key)%")
        pci_scores+=("$(get_historical_score 'PCI' $month_key)%")
        pci4_scores+=("$(get_historical_score 'PCI4' $month_key)%")
        
        # Move to next month
        current_month=$((current_month + 1))
        if [[ $current_month -gt 12 ]]; then
            current_month=1
        fi
    done
    
    printf "\n"
    printf "Historical scores per framework as recorded in monthly report. (N/A = Score not yet saved in DB)\n"
    printf "===========================================================================\n"
    printf "%-22s%-8s%-8s%-8s%-8s%-8s%-8s\n" "Month" "${months[0]}" "${months[1]}" "${months[2]}" "${months[3]}" "${months[4]}" "${months[5]}"
    printf "\n"
    printf "%-22s%-8s%-8s%-8s%-8s%-8s%-8s\n" "AWS Scores:" "${aws_scores[0]}" "${aws_scores[1]}" "${aws_scores[2]}" "${aws_scores[3]}" "${aws_scores[4]}" "${aws_scores[5]}"
    printf "%-22s%-8s%-8s%-8s%-8s%-8s%-8s\n" "CIS Scores:" "${cis_scores[0]}" "${cis_scores[1]}" "${cis_scores[2]}" "${cis_scores[3]}" "${cis_scores[4]}" "${cis_scores[5]}"
    printf "%-22s%-8s%-8s%-8s%-8s%-8s%-8s\n" "CIS v1.4 Scores:" "${cis14_scores[0]}" "${cis14_scores[1]}" "${cis14_scores[2]}" "${cis14_scores[3]}" "${cis14_scores[4]}" "${cis14_scores[5]}"
    printf "%-22s%-8s%-8s%-8s%-8s%-8s%-8s\n" "CIS v3.0 Scores:" "${cis30_scores[0]}" "${cis30_scores[1]}" "${cis30_scores[2]}" "${cis30_scores[3]}" "${cis30_scores[4]}" "${cis30_scores[5]}"
    printf "%-22s%-8s%-8s%-8s%-8s%-8s%-8s\n" "PCI Scores:" "${pci_scores[0]}" "${pci_scores[1]}" "${pci_scores[2]}" "${pci_scores[3]}" "${pci_scores[4]}" "${pci_scores[5]}"
    printf "%-22s%-8s%-8s%-8s%-8s%-8s%-8s\n" "PCI v4 Scores:" "${pci4_scores[0]}" "${pci4_scores[1]}" "${pci4_scores[2]}" "${pci4_scores[3]}" "${pci4_scores[4]}" "${pci4_scores[5]}"
    printf "\n"
}

printf "\n"
printf "================================================================================\n"
printf "COMPLIANCE FRAMEWORKS STATUS CHECK\n"
printf "================================================================================\n"

# Get all enabled standards
enabled_standards=$(aws securityhub get-enabled-standards --output json 2>/dev/null)

if [[ -z "$enabled_standards" ]] || [[ "$enabled_standards" == "null" ]]; then
    printf "❌ Unable to retrieve Security Hub standards - Security Hub may not be enabled\n"
    exit 1
fi

# Framework ARN patterns to check
declare -A framework_patterns=(
    ["CIS_AWS_Foundations_v3_0_0"]="cis-aws-foundations-benchmark/v/3.0.0"
    ["PCI_DSS_v4_0_1"]="pci-dss/v/4.0.1"  
    ["CIS_AWS_Foundations_v1_4_0"]="cis-aws-foundations-benchmark/v/1.4.0"
)

# Framework display names
declare -A framework_display=(
    ["CIS_AWS_Foundations_v3_0_0"]="CIS AWS Foundations Benchmark v3.0.0"
    ["PCI_DSS_v4_0_1"]="PCI DSS v4.0.1"
    ["CIS_AWS_Foundations_v1_4_0"]="CIS AWS Foundations Benchmark v1.4.0"
)

# Check each framework
for framework in "${!framework_patterns[@]}"; do
    pattern="${framework_patterns[$framework]}"
    display_name="${framework_display[$framework]}"
    
    # Check if framework is enabled
    is_enabled=$(echo "$enabled_standards" | jq -r --arg pattern "$pattern" '.StandardsSubscriptions[] | select(.StandardsArn | contains($pattern)) | .StandardsStatus')
    
    if [[ "$is_enabled" == "READY" ]]; then
        printf "✅ %-40s: ENABLED\n" "$display_name"
        export "${framework}_ENABLED"=true
    elif [[ "$is_enabled" == "INCOMPLETE" ]]; then
        printf "⚠️  %-40s: PARTIALLY ENABLED\n" "$display_name"
        export "${framework}_ENABLED"=partial
    else
        printf "❌ %-40s: NOT ENABLED\n" "$display_name"
        export "${framework}_ENABLED"=false
    fi
done

printf "\n"

# Generate historical scores table
generate_historical_scores
