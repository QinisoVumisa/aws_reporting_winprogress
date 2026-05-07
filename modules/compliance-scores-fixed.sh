#!/bin/bash

# Function to get historical score directly from Security Hub with enhanced error handling and comprehensive framework support
get_historical_score_from_securityhub() {
    local framework="$1"
    local target_month="$2"
    local target_year="$3"
    
    # Validate input parameters
    if [[ -z "$framework" ]] || [[ -z "$target_month" ]] || [[ -z "$target_year" ]]; then
        echo "N/A"
        return
    fi
    
    # Calculate date range with leap year support
    local date_range=$(calculate_month_date_range "$target_month" "$target_year")
    if [[ $? -ne 0 ]] || [[ -z "$date_range" ]]; then
        echo "N/A"
        return
    fi
    
    local start_date=$(echo "$date_range" | cut -d'|' -f1)
    local end_date=$(echo "$date_range" | cut -d'|' -f2)
    
    # Only calculate for past months (avoid future dates)
    local current_date=$(date +%Y-%m-%d 2>/dev/null)
    if [[ -z "$current_date" ]] || [[ "$end_date" > "$current_date" ]]; then
        echo "N/A"
        return
    fi
    
    # For current month or very recent months, try to get current compliance state
    local is_current_month=false
    local current_month=$(date +%m 2>/dev/null | sed 's/^0*//' 2>/dev/null)
    local current_year=$(date +%Y 2>/dev/null)
    
    if [[ -z "$current_month" ]] || [[ -z "$current_year" ]]; then
        echo "N/A"
        return
    fi
    
    if [[ "$target_year" == "$current_year" ]] && [[ "$target_month" == "$current_month" ]]; then
        is_current_month=true
    fi
    
    local findings_result=""
    local securityhub_command=""
    
    # Choose between current state and historical query based on recency
    local use_current_state=false
    if [[ $is_current_month == true ]] || [[ $((current_year * 12 + current_month - target_year * 12 - target_month)) -le 2 ]]; then
        use_current_state=true
    fi
    
    # Framework-specific Security Hub queries with comprehensive coverage
    case "$framework" in
        "AWS")
            if [[ $use_current_state == true ]]; then
                securityhub_command='aws securityhub get-findings --filters '"'"'{"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            else
                securityhub_command='aws securityhub get-findings --filters '"'"'{"UpdatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            fi
            ;;
        "CIS"|"CIS12")
            if [[ $use_current_state == true ]]; then
                securityhub_command='aws securityhub get-findings --filters '"'"'{"ProductFields":[{"Key":"StandardsGuideArn","Value":"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            else
                securityhub_command='aws securityhub get-findings --filters '"'"'{"UpdatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"ProductFields":[{"Key":"StandardsGuideArn","Value":"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            fi
            ;;
        "CIS14")
            if [[ $use_current_state == true ]]; then
                securityhub_command='aws securityhub get-findings --filters '"'"'{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/1.4.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            else
                securityhub_command='aws securityhub get-findings --filters '"'"'{"UpdatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/1.4.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            fi
            ;;
        "CIS30")
            if [[ $use_current_state == true ]]; then
                securityhub_command='aws securityhub get-findings --filters '"'"'{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/3.0.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            else
                securityhub_command='aws securityhub get-findings --filters '"'"'{"UpdatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/3.0.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            fi
            ;;
        "PCI"|"PCI32")
            if [[ $use_current_state == true ]]; then
                securityhub_command='aws securityhub get-findings --filters '"'"'{"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/pci-dss/v/3.2.1","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            else
                securityhub_command='aws securityhub get-findings --filters '"'"'{"UpdatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/pci-dss/v/3.2.1","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            fi
            ;;
        "PCI4"|"PCI40")
            if [[ $use_current_state == true ]]; then
                securityhub_command='aws securityhub get-findings --filters '"'"'{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "pci-dss/v/4.0.1","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            else
                securityhub_command='aws securityhub get-findings --filters '"'"'{"UpdatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "pci-dss/v/4.0.1","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            fi
            ;;
        *)
            echo "N/A"
            return
            ;;
    esac
    
    # Execute Security Hub command with comprehensive error handling
    if [[ -n "$securityhub_command" ]]; then
        findings_result=$(eval "$securityhub_command" 2>/dev/null)
        local exit_code=$?
        
        # Check if command executed successfully
        if [[ $exit_code -ne 0 ]]; then
            echo "N/A"
            return
        fi
    else
        echo "N/A"
        return
    fi
    
    # Validate findings result
    if [[ -z "$findings_result" ]] || \
       [[ "$findings_result" == "null" ]] || \
       [[ "$findings_result" == '{"Findings":[]}' ]] || \
       [[ "$findings_result" =~ "error" ]] || \
       [[ "$findings_result" =~ "Error" ]]; then
        echo "N/A"
        return
    fi
    
    # Calculate score from findings with enhanced error handling
    local total_controls=0
    local failed_controls=0
    
    # Extract total controls with error handling
    if command -v jq >/dev/null 2>&1; then
        total_controls=$(echo "$findings_result" | jq -r ".Findings[].GeneratorId" 2>/dev/null | sort 2>/dev/null | uniq 2>/dev/null | wc -l 2>/dev/null)
        failed_controls=$(echo "$findings_result" | jq -r '.Findings[] | select(.Compliance.Status != "PASSED") | .GeneratorId' 2>/dev/null | sort 2>/dev/null | uniq 2>/dev/null | wc -l 2>/dev/null)
    else
        echo "N/A"
        return
    fi
    
    # Validate control counts
    if [[ ! "$total_controls" =~ ^[0-9]+$ ]] || [[ ! "$failed_controls" =~ ^[0-9]+$ ]] || [[ $total_controls -lt 1 ]]; then
        echo "N/A"
        return
    fi
    
    # Calculate score with error handling
    local passed_controls=$((total_controls - failed_controls))
    local score=""
    
    if command -v awk >/dev/null 2>&1 && [[ $total_controls -gt 0 ]]; then
        score=$(awk "BEGIN { pc=100*${passed_controls}/${total_controls}; i=int(pc); print (pc-i<0.5)?i:i+1 }" 2>/dev/null)
    fi
    
    # Validate and return score
    if [[ "$score" =~ ^[0-9]+$ ]] && [[ $score -ge 0 ]] && [[ $score -le 100 ]]; then
        echo "$score"
    else
        echo "N/A"
    fi
}

# Function to calculate proper date range for any month/year with leap year support
calculate_month_date_range() {
    local target_month="$1"
    local target_year="$2"
    
    # Calculate start date
    local start_date="${target_year}-$(printf '%02d' $target_month)-01"
    local end_date=""
    
    # Calculate end date based on month with leap year support
    case "$target_month" in
        1|3|5|7|8|10|12)
            end_date="${target_year}-$(printf '%02d' $target_month)-31"
            ;;
        4|6|9|11)
            end_date="${target_year}-$(printf '%02d' $target_month)-30"
            ;;
        2)
            # Handle February with leap year calculation
            if [[ $((target_year % 4)) -eq 0 ]] && [[ $((target_year % 100)) -ne 0 || $((target_year % 400)) -eq 0 ]]; then
                end_date="${target_year}-02-29"
            else
                end_date="${target_year}-02-28"
            fi
            ;;
        *)
            return 1
            ;;
    esac
    
    echo "$start_date|$end_date"
}

# Enhanced function to calculate historical score from Security Hub with comprehensive framework support
calculate_historical_score_from_securityhub() {
    local framework="$1"
    local target_month="$2"
    local target_year="$3"
    
    # Validate input parameters
    if [[ -z "$framework" ]] || [[ -z "$target_month" ]] || [[ -z "$target_year" ]]; then
        echo "N/A"
        return
    fi
    
    # Calculate date range with leap year support
    local date_range=$(calculate_month_date_range "$target_month" "$target_year")
    if [[ $? -ne 0 ]] || [[ -z "$date_range" ]]; then
        echo "N/A"
        return
    fi
    
    local start_date=$(echo "$date_range" | cut -d'|' -f1)
    local end_date=$(echo "$date_range" | cut -d'|' -f2)
    
    # Only calculate for past months (avoid future dates)
    local current_date=$(date +%Y-%m-%d 2>/dev/null)
    if [[ -z "$current_date" ]] || [[ "$end_date" > "$current_date" ]]; then
        echo "N/A"
        return
    fi
    
    # Framework-specific Security Hub queries with comprehensive coverage
    local findings_result=""
    local securityhub_command=""
    
    case "$framework" in
        "AWS")
            # Try both UpdatedAt and CreatedAt for better coverage
            securityhub_command='aws securityhub get-findings --filters '"'"'{"CreatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            ;;
        "CIS"|"CIS12")
            securityhub_command='aws securityhub get-findings --filters '"'"'{"CreatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"ProductFields":[{"Key":"StandardsGuideArn","Value":"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            ;;
        "CIS14")
            securityhub_command='aws securityhub get-findings --filters '"'"'{"CreatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/1.4.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            ;;
        "CIS30")
            securityhub_command='aws securityhub get-findings --filters '"'"'{"CreatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "cis-aws-foundations-benchmark/v/3.0.0","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            ;;
        "PCI"|"PCI32")
            securityhub_command='aws securityhub get-findings --filters '"'"'{"CreatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"ProductFields":[{"Key":"StandardsArn","Value":"arn:aws:securityhub:::standards/pci-dss/v/3.2.1","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            ;;
        "PCI4"|"PCI40")
            securityhub_command='aws securityhub get-findings --filters '"'"'{"CreatedAt": [{"Start":"'"$start_date"'","End":"'"$end_date"'"}],"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"GeneratorId": [{"Value": "pci-dss/v/4.0.1","Comparison": "PREFIX"}],"WorkflowStatus":[{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}'"'"' --max-results 100'
            ;;
        *)
            echo "N/A"
            return
            ;;
    esac
    
    # Execute Security Hub command with comprehensive error handling
    if [[ -n "$securityhub_command" ]]; then
        findings_result=$(eval "$securityhub_command" 2>/dev/null)
        local exit_code=$?
        
        # Check if command executed successfully
        if [[ $exit_code -ne 0 ]]; then
            echo "N/A"
            return
        fi
    else
        echo "N/A"
        return
    fi
    
    # Validate findings result
    if [[ -z "$findings_result" ]] || \
       [[ "$findings_result" == "null" ]] || \
       [[ "$findings_result" == '{"Findings":[]}' ]] || \
       [[ "$findings_result" =~ "error" ]] || \
       [[ "$findings_result" =~ "Error" ]]; then
        echo "N/A"
        return
    fi
    
    # Calculate score from findings with enhanced error handling
    local total_controls=0
    local failed_controls=0
    
    if command -v jq >/dev/null 2>&1; then
        total_controls=$(echo "$findings_result" | jq -r ".Findings[].GeneratorId" 2>/dev/null | sort 2>/dev/null | uniq 2>/dev/null | wc -l 2>/dev/null)
        failed_controls=$(echo "$findings_result" | jq -r '.Findings[] | select(.Compliance.Status != "PASSED") | .GeneratorId' 2>/dev/null | sort 2>/dev/null | uniq 2>/dev/null | wc -l 2>/dev/null)
    else
        echo "N/A"
        return
    fi
    
    # Validate control counts
    if [[ ! "$total_controls" =~ ^[0-9]+$ ]] || [[ ! "$failed_controls" =~ ^[0-9]+$ ]] || [[ $total_controls -lt 1 ]]; then
        echo "N/A"
        return
    fi
    
    # Calculate score with error handling
    local passed_controls=$((total_controls - failed_controls))
    local score=""
    
    if command -v awk >/dev/null 2>&1 && [[ $total_controls -gt 0 ]]; then
        score=$(awk "BEGIN { pc=100*${passed_controls}/${total_controls}; i=int(pc); print (pc-i<0.5)?i:i+1 }" 2>/dev/null)
    fi
    
    # Validate and return score
    if [[ "$score" =~ ^[0-9]+$ ]] && [[ $score -ge 0 ]] && [[ $score -le 100 ]]; then
        echo "$score"
    else
        echo "N/A"
    fi
}

# Function to execute DynamoDB commands with fallback logic
execute_dynamodb_with_fallback() {
    local operation="$1"
    local table_name="$2"
    local key="$3"
    local update_expression="$4"
    local expression_attribute_values="$5"
    
    # Try with instance profile first
    local command="aws dynamodb $operation --table-name \"$table_name\" --key '$key'"
    if [[ -n "$update_expression" ]]; then
        command+=" --update-expression '$update_expression'"
    fi
    if [[ -n "$expression_attribute_values" ]]; then
        command+=" --expression-attribute-values '$expression_attribute_values'"
    fi
    
    # Execute with instance profile
    local result=$(eval "$command" 2>/dev/null)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]] && [[ -n "$result" ]]; then
        echo "$result"
        return 0
    fi
    
    # Fallback: Try with default credentials (no profile)
    command="AWS_PROFILE= aws dynamodb $operation --table-name \"$table_name\" --key '$key'"
    if [[ -n "$update_expression" ]]; then
        command+=" --update-expression '$update_expression'"
    fi
    if [[ -n "$expression_attribute_values" ]]; then
        command+=" --expression-attribute-values '$expression_attribute_values'"
    fi
    
    # Execute with default credentials
    result=$(eval "$command" 2>/dev/null)
    exit_code=$?
    
    if [[ $exit_code -eq 0 ]] && [[ -n "$result" ]]; then
        echo "$result"
        return 0
    fi
    
    return 1
}

# Function to validate DynamoDB response
validate_dynamodb_response() {
    local response="$1"
    
    # Check if response is empty, null, or contains error indicators
    if [[ -z "$response" ]] || \
       [[ "$response" == "null" ]] || \
       [[ "$response" == "{}" ]] || \
       [[ "$response" =~ "error" ]] || \
       [[ "$response" =~ "Error" ]] || \
       [[ "$response" =~ "exception" ]] || \
       [[ "$response" =~ "Exception" ]]; then
        return 1
    fi
    
    # Check if it's a valid numeric score (0-100)
    if [[ "$response" =~ ^[0-9]+$ ]] && [[ "$response" -ge 0 ]] && [[ "$response" -le 100 ]]; then
        return 0
    fi
    
    return 1
}

# Function to get score from DynamoDB with enhanced error handling
get_score_from_dynamodb() {
    local framework="$1"
    local target_month="$2"
    local use_profile="$3"  # true/false for instance profile
    
    if [[ -z "$accountid" ]]; then
        return 1
    fi
    
    local dynamodb_command=""
    local column_name="${framework}${target_month}"
    
    # Build the DynamoDB command with or without profile
    if [[ "$use_profile" == "true" ]]; then
        dynamodb_command="aws dynamodb get-item --table-name \"mcs-customer-sechub-scores\" --key \"{\\\"SecHubAccountId\\\":{\\\"N\\\":\\\"$accountid\\\"}}\" --projection-expression \"$column_name\""
    else
        dynamodb_command="AWS_PROFILE= aws dynamodb get-item --table-name \"mcs-customer-sechub-scores\" --key \"{\\\"SecHubAccountId\\\":{\\\"N\\\":\\\"$accountid\\\"}}\" --projection-expression \"$column_name\""
    fi
    
    # Execute the command with comprehensive error suppression
    local raw_response=$(eval "$dynamodb_command" 2>/dev/null)
    local exit_code=$?
    
    # Check if command executed successfully
    if [[ $exit_code -ne 0 ]] || [[ -z "$raw_response" ]]; then
        return 1
    fi
    
    # Extract the score value with error handling
    local score_value=$(echo "$raw_response" | jq -r ".Item.$column_name.N" 2>/dev/null)
    
    # Validate the extracted score
    if validate_dynamodb_response "$score_value"; then
        echo "$score_value"
        return 0
    fi
    
    return 1
}

# Function to check DynamoDB table accessibility
check_dynamodb_table_access() {
    local use_profile="$1"
    
    local describe_command=""
    if [[ "$use_profile" == "true" ]]; then
        describe_command="aws dynamodb describe-table --table-name \"mcs-customer-sechub-scores\""
    else
        describe_command="AWS_PROFILE= aws dynamodb describe-table --table-name \"mcs-customer-sechub-scores\""
    fi
    
    local table_status=$(eval "$describe_command" 2>/dev/null | jq -r '.Table.TableStatus' 2>/dev/null)
    
    if [[ "$table_status" == "ACTIVE" ]]; then
        return 0
    fi
    
    return 1
}

# Enhanced function with multi-level fallback logic for all frameworks
get_historical_score_with_fallback() {
    local framework="$1"
    local target_month="$2"
    local target_year="$3"
    
    # Validate input parameters
    if [[ -z "$framework" ]] || [[ -z "$target_month" ]] || [[ -z "$target_year" ]]; then
        echo "N/A"
        return
    fi
    
    # Ensure target_month is properly formatted (remove leading zeros for processing)
    target_month=$(echo "$target_month" | sed 's/^0*//')
    if [[ -z "$target_month" ]]; then
        target_month="1"
    fi
    
    # Map framework names to DynamoDB column names
    local db_framework=""
    case "$framework" in
        "AWS")
            db_framework="AWS"
            ;;
        "CIS"|"CIS12")
            db_framework="CIS"
            ;;
        "CIS14")
            db_framework="CIS14"
            ;;
        "CIS30")
            db_framework="CIS30"
            ;;
        "PCI"|"PCI32")
            db_framework="PCI"
            ;;
        "PCI4"|"PCI40")
            db_framework="PCI4"
            ;;
        *)
            # If framework not recognized, skip DynamoDB and go to Security Hub
            calculate_historical_score_from_securityhub "$framework" "$target_month" "$target_year"
            return
            ;;
    esac
    
    local score_from_db=""
    
    # PRIMARY: Try DynamoDB with instance profile
    if check_dynamodb_table_access "true"; then
        score_from_db=$(get_score_from_dynamodb "$db_framework" "$target_month" "true")
        if [[ $? -eq 0 ]] && [[ -n "$score_from_db" ]]; then
            echo "$score_from_db"
            return
        fi
    fi
    
    # SECONDARY: Try DynamoDB with default AWS credentials (no profile)
    if check_dynamodb_table_access "false"; then
        score_from_db=$(get_score_from_dynamodb "$db_framework" "$target_month" "false")
        if [[ $? -eq 0 ]] && [[ -n "$score_from_db" ]]; then
            echo "$score_from_db"
            return
        fi
    fi
    
    # TERTIARY: Fall back to Security Hub historical calculation
    calculate_historical_score_from_securityhub "$framework" "$target_month" "$target_year"
}

# Enhanced debug function to test historical score retrieval with comprehensive diagnostics for all frameworks
debug_historical_scores() {
    echo "=== ENHANCED DEBUGGING HISTORICAL SCORES (ALL FRAMEWORKS) ==="
    echo "Account ID: $accountid"
    echo "Current month number: $thismonthnumber"
    echo "Script execution date: $(date)"
    
    # Test AWS CLI availability
    if command -v aws >/dev/null 2>&1; then
        echo "✓ AWS CLI is available"
        
        # Test basic AWS connectivity
        local identity_test=$(aws sts get-caller-identity 2>/dev/null)
        if [[ $? -eq 0 ]] && [[ -n "$identity_test" ]]; then
            echo "✓ AWS credentials are working"
            local current_account=$(echo "$identity_test" | jq -r '.Account' 2>/dev/null)
            echo "  Current AWS Account: $current_account"
        else
            echo "✗ AWS credentials test failed"
        fi
    else
        echo "✗ AWS CLI not found"
    fi
    
    # Test jq availability
    if command -v jq >/dev/null 2>&1; then
        echo "✓ jq is available"
    else
        echo "✗ jq not found - JSON parsing will fail"
    fi
    
    echo ""
    echo "--- DynamoDB Accessibility Tests ---"
    
    # Test DynamoDB table access with instance profile
    echo "Testing DynamoDB with instance profile..."
    if check_dynamodb_table_access "true"; then
        echo "✓ DynamoDB table accessible with instance profile"
        
        # Test data retrieval for different frameworks
        local frameworks=("AWS" "CIS" "CIS14" "CIS30" "PCI" "PCI4")
        for fw in "${frameworks[@]}"; do
            local test_score=$(get_score_from_dynamodb "$fw" "$thismonthnumber" "true")
            if [[ $? -eq 0 ]] && [[ -n "$test_score" ]]; then
                echo "✓ Successfully retrieved $fw score with instance profile: $test_score"
            else
                echo "⚠ Instance profile works but no $fw score data found for month $thismonthnumber"
            fi
        done
    else
        echo "✗ DynamoDB table not accessible with instance profile"
    fi
    
    # Test DynamoDB table access with default credentials
    echo ""
    echo "Testing DynamoDB with default credentials..."
    if check_dynamodb_table_access "false"; then
        echo "✓ DynamoDB table accessible with default credentials"
        
        # Test data retrieval for different frameworks
        local frameworks=("AWS" "CIS" "CIS14" "CIS30" "PCI" "PCI4")
        for fw in "${frameworks[@]}"; do
            local test_score=$(get_score_from_dynamodb "$fw" "$thismonthnumber" "false")
            if [[ $? -eq 0 ]] && [[ -n "$test_score" ]]; then
                echo "✓ Successfully retrieved $fw score with default credentials: $test_score"
            else
                echo "⚠ Default credentials work but no $fw score data found for month $thismonthnumber"
            fi
        done
    else
        echo "✗ DynamoDB table not accessible with default credentials"
    fi
    
    echo ""
    echo "--- Security Hub Fallback Tests ---"
    
    # Test Security Hub access
    local securityhub_test=$(aws securityhub get-enabled-standards 2>/dev/null)
    if [[ $? -eq 0 ]] && [[ -n "$securityhub_test" ]]; then
        echo "✓ Security Hub is accessible"
        
        # Test historical score calculation from Security Hub for all frameworks
        local current_year=$(date +%Y)
        local current_month=$(echo "$thismonthnumber" | sed 's/^0*//')
        
        local security_frameworks=("AWS" "CIS" "CIS14" "CIS30" "PCI" "PCI4")
        for fw in "${security_frameworks[@]}"; do
            echo "Testing Security Hub $fw score calculation..."
            local securityhub_score=$(get_historical_score_from_securityhub "$fw" "$current_month" "$current_year")
            echo "  Security Hub $fw score for current month: $securityhub_score"
        done
    else
        echo "✗ Security Hub not accessible or not enabled"
    fi
    
    echo ""
    echo "--- Full Fallback Chain Tests ---"
    
    # Test the complete fallback chain for all frameworks
    local current_year=$(date +%Y)
    local current_month=$(echo "$thismonthnumber" | sed 's/^0*//')
    
    local all_frameworks=("AWS" "CIS" "CIS14" "CIS30" "PCI" "PCI4")
    for fw in "${all_frameworks[@]}"; do
        echo "Testing complete fallback chain for $fw..."
        local final_score=$(get_historical_score_with_fallback "$fw" "$current_month" "$current_year")
        echo "  Final $fw score using complete fallback chain: $final_score"
    done
    
    echo ""
    echo "--- Date Range Calculation Test ---"
    
    # Test date range calculation for different months
    echo "Testing date range calculations:"
    local test_months=(1 2 3 4 5 6 7 8 9 10 11 12)
    local test_year=$(date +%Y)  # Use current year instead of hardcoded 2024
    for month in "${test_months[@]}"; do
        local date_range=$(calculate_month_date_range "$month" "$test_year")
        if [[ $? -eq 0 ]]; then
            echo "  Month $month/$test_year: $date_range"
        else
            echo "  Month $month/$test_year: ERROR"
        fi
    done
    
    echo ""
    echo "--- Sample Data Structure Test ---"
    
    # Show sample of DynamoDB item structure (if accessible)
    local sample_item=""
    if check_dynamodb_table_access "true"; then
        sample_item=$(aws dynamodb get-item --table-name "mcs-customer-sechub-scores" --key "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" 2>/dev/null)
    elif check_dynamodb_table_access "false"; then
        sample_item=$(AWS_PROFILE= aws dynamodb get-item --table-name "mcs-customer-sechub-scores" --key "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" 2>/dev/null)
    fi
    
    if [[ -n "$sample_item" ]] && [[ "$sample_item" != "{}" ]]; then
        echo "Sample DynamoDB item structure:"
        echo "$sample_item" | jq '.' 2>/dev/null || echo "$sample_item"
    else
        echo "No DynamoDB data found for account $accountid"
    fi
    
    echo "=== END ENHANCED DEBUG ==="
}

#======Get Account Context with Enhanced Error Handling ============================
# Get AWS account identity with comprehensive error handling
calleridentity=""
accountid=""

# Try to get caller identity with multiple approaches
if command -v aws >/dev/null 2>&1; then
    # Primary attempt with instance profile
    calleridentity=$(aws sts get-caller-identity --output json 2>/dev/null)
    
    # If that fails, try with default credentials
    if [[ -z "$calleridentity" ]] || [[ "$calleridentity" =~ "error" ]]; then
        calleridentity=$(AWS_PROFILE= aws sts get-caller-identity --output json 2>/dev/null)
    fi
    
    # Extract account ID if we have valid response
    if [[ -n "$calleridentity" ]] && [[ ${#calleridentity} -gt 2 ]] && [[ "$calleridentity" != "null" ]]; then
        if command -v jq >/dev/null 2>&1; then
            accountid=$(echo "$calleridentity" | jq -r '.Account' 2>/dev/null)
            
            # Validate account ID format (12 digits)
            if [[ ! "$accountid" =~ ^[0-9]{12}$ ]]; then
                echo "Warning: Invalid account ID format detected: $accountid"
                accountid=""
            fi
        else
            echo "Warning: jq not available - cannot parse account ID"
        fi
    else
        echo "Warning: Unable to retrieve AWS account identity"
    fi
else
    echo "Error: AWS CLI not found"
    exit 1
fi

# Validate we have a valid account ID before proceeding
if [[ -z "$accountid" ]]; then
    echo "Error: Could not determine AWS account ID. Please check AWS credentials."
    echo "Available AWS configuration:"
    aws configure list 2>/dev/null || echo "  No AWS configuration found"
    exit 1
fi

echo "Successfully identified AWS Account: $accountid"

# Date calculations with enhanced error handling
if command -v date >/dev/null 2>&1; then
    thismonthnumber=$(date -d "$(date +%Y-%m-01)" +%m 2>/dev/null)
    today=$(date +"%Y-%m-%d" 2>/dev/null)
    day=$(date +"%d" 2>/dev/null)
    dateyesterday=$(date -d "03:00 yesterday" '+%Y-%m-%d' 2>/dev/null)
    
    # Validate date calculations
    if [[ -z "$thismonthnumber" ]] || [[ -z "$today" ]] || [[ -z "$day" ]] || [[ -z "$dateyesterday" ]]; then
        echo "Error: Date calculation failed. Please check system date configuration."
        exit 1
    fi
    
    echo "Date context - Month: $thismonthnumber, Today: $today, Yesterday: $dateyesterday"
else
    echo "Error: date command not available"
    exit 1
fi

export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10

#write customer name to the DynamoDB score-tracking table (optional - can be removed if not needed)
# if [[ "$custname" ]]; then
#     execute_dynamodb_with_fallback "update-item" "mcs-customer-sechub-scores" "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" "SET ACustomerName = :NewCustomerName" "{\":NewCustomerName\" : {\"S\":\"$custname\"}}"
# fi

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
let awspasses=($totalnumberawscontrolsreportingstatus-$totalnumberawscontrolsnotpassed)
if [[ $totalnumberawscontrolsreportingstatus -lt 1 ]]; then 
    printf "AWS Control Enumeration Issue Detected\n"
    awsfoundationalscore="N/A"
else
    awsfoundationalscore=$(awk "BEGIN { pc=100*${awspasses}/${totalnumberawscontrolsreportingstatus}; i=int(pc); print (pc-i<0.5)?i:i+1 }")
fi

let cispasses=($totalnumberciscontrolsreportingstatus-$totalnumberciscontrolsnotpassed)
if [[ $totalnumberciscontrolsreportingstatus -lt 1 ]]; then 
    printf "CIS Control Enumeration Issue Detected\n"
    cisfoundationsscore="N/A"
else
    cisfoundationsscore=$(awk "BEGIN { pc=100*${cispasses}/${totalnumberciscontrolsreportingstatus}; i=int(pc); print (pc-i<0.5)?i:i+1 }")
fi

let pcipasses=($totalnumberpcicontrolsreportingstatus-$totalnumberpcicontrolsnotpassed)
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
    let cis14foundationspasses=($totalnumbercis14controlsreportingstatus-$totalnumbercis14controlsnotpassed)
    
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
    let cis30foundationspasses=($totalnumbercis30controlsreportingstatus-$totalnumbercis30controlsnotpassed)
    
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
    let pci4passes=($totalnumberpci4controlsreportingstatus-$totalnumberpci4controlsnotpassed)
    
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
printf "AWS Controls - Reporting Status        : %-12s CIS Controls - Reporting Status        : %-12s PCI Controls - Reporting Status        : %s\n" "$totalnumberawscontrolsreportingstatus" "$totalnumberciscontrolsreportingstatus" "$totalnumberpcicontrolsreportingstatus"
printf "AWS Controls - Failed                  : %-12s CIS Controls - Failed                  : %-12s PCI Controls - Failed                  : %s\n" "$totalnumberawscontrolsfailed" "$totalnumberciscontrolsfailed" "$totalnumberpcicontrolsfailed"
printf "AWS Controls - Pass                    : %-12s CIS Controls - Pass                    : %-12s PCI Controls - Pass                    : %s\n" "$awspasses" "$cispasses" "$pcipasses"
printf "AWS Foundations Score:           : %-12s CIS Foundations Score:           : %-12s PCI Score:                       : %s\n" "$awsfoundationalscore%" "$cisfoundationsscore%" "$pciscore%"

printf "\n"

printf "CIS v1.4 Controls - Reporting Status  : %-15s CIS v3.0  Controls - Reporting Status : %-15s PCI v4.0.1 Controls - Reporting Status  : %s\n" "$totalnumbercis14controlsreportingstatus" "$totalnumbercis30controlsreportingstatus" "$totalnumberpci4controlsreportingstatus"
printf "CIS v1.4 Controls - Failed            : %-15s CIS v3.0  Controls - Failed           : %-15s PCI v4.0.1 Controls - Failed            : %s\n" "$totalnumbercis14controlsfailed" "$totalnumbercis30controlsfailed" "$totalnumberpci4controlsfailed"
printf "CIS v1.4 Controls - Pass              : %-15s CIS v3.0  Controls - Passed           : %-15s PCI v4.0.1 Controls - Pass              : %s\n" "$cis14foundationspasses" "$cis30foundationspasses" "$pci4passes"

if [[ -n "$cis14enumissue" ]]; then printf "$cis14enumissue\n"; fi
if [[ -n "$cis30enumissue" ]]; then printf "$cis30enumissue\n"; fi
if [[ -n "$pci4enumissue" ]]; then printf "$pci4enumissue\n"; fi

printf "CIS v1.4 Foundations Score:           : %-15s CIS v3.0 Foundations Score:           : %-15s PCI v4.0.1 Score:                       : %s\n" "$cis14foundationsscore%" "$cis30foundationsscore%" "$pci4score%"

# Optional: write the latest compliance scores to DynamoDB - ONLY IF THIS IS RUN ON THE 1st to the 5th of the month!
# Comment out this section if you don't want to use DynamoDB
# day2=$(date +"%Oe"| sed 's/ //')
# if [[ day2 -le 5 ]]; then
#     # AWS Score - Using fallback function
#     if [[ "$awsfoundationalscore" != "N/A" ]]; then
#         execute_dynamodb_with_fallback "update-item" "mcs-customer-sechub-scores" "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" "SET AWS$thismonthnumber = :NewScore" "{\":NewScore\" : {\"N\":\"$awsfoundationalscore\"}}"
#     fi
#     
#     # CIS Score - Using fallback function
#     if [[ "$cisfoundationsscore" != "N/A" ]]; then
#         execute_dynamodb_with_fallback "update-item" "mcs-customer-sechub-scores" "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" "SET CIS$thismonthnumber = :NewScore" "{\":NewScore\" : {\"N\":\"$cisfoundationsscore\"}}"
#     fi
#     
#     # PCI Score - Using fallback function
#     if [[ "$pciscore" != "N/A" ]]; then
#         execute_dynamodb_with_fallback "update-item" "mcs-customer-sechub-scores" "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" "SET PCI$thismonthnumber = :NewScore" "{\":NewScore\" : {\"N\":\"$pciscore\"}}"
#     fi

#     # Update new framework scores with enhanced error handling and validation
#     if [[ -n "$cis14foundationsscore" ]] && [[ "$cis14foundationsscore" != "N/A" ]]; then
#         execute_dynamodb_with_fallback "update-item" "mcs-customer-sechub-scores" "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" "SET CIS14$thismonthnumber = :NewScore" "{\":NewScore\" : {\"N\":\"$cis14foundationsscore\"}}"
#     fi

#     if [[ -n "$cis30foundationsscore" ]] && [[ "$cis30foundationsscore" != "N/A" ]]; then
#         execute_dynamodb_with_fallback "update-item" "mcs-customer-sechub-scores" "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" "SET CIS30$thismonthnumber = :NewScore" "{\":NewScore\" : {\"N\":\"$cis30foundationsscore\"}}"
#     fi

#     if [[ -n "$pci4score" ]] && [[ "$pci4score" != "N/A" ]]; then
#         execute_dynamodb_with_fallback "update-item" "mcs-customer-sechub-scores" "{\"SecHubAccountId\":{\"N\":\"$accountid\"}}" "SET PCI4$thismonthnumber = :NewScore" "{\":NewScore\" : {\"N\":\"$pci4score\"}}"
#     fi
# fi

#   Write the historical scores matrix to screen - retrieving live from Security Hub
printf "\n\nHistorical scores per framework (calculated live from Security Hub). (N/A = No data for this month)\n"
printf "===========================================================================\n"

# Debug historical scores (comment out in production)
# debug_historical_scores

printf "Month                    "

loopcounter=5
while [ $loopcounter -ge 0 ]
do
        echo -n `date --date="$today -$loopcounter month" +%b`
        echo -ne "     "
        ((loopcounter--))
done

printf "\n\n"

# AWS LOOP - PULL HISTORICAL SCORES FROM SECURITY HUB or DynamoDB
printf "AWS Scores:          "

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d'$scoremonthcounter)
    fi
    
    # Calculate target year and month with proper numeric comparison for AWS
    current_year=$(date +%Y)
    current_month_num=$(echo "$thismonthnumber" | sed 's/^0*//')
    score_month_num=$(echo "$scoremonthcounter" | sed 's/^0*//')
    
    # If the score month is greater than current month, it's from last year
    if [[ $score_month_num -gt $current_month_num ]]; then
        target_year=$((current_year - 1))
    else
        target_year=$current_year
    fi
    
    # Get historical score with DynamoDB fallback to Security Hub
    historical_score=$(get_historical_score_with_fallback "AWS" "$scoremonthcounter" "$target_year")
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "    "
    ((loopcounter--))
done

printf "\n"

# CIS LOOP - PULL HISTORICAL SCORES FROM SECURITY HUB
printf "CIS Scores:          "

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d'$scoremonthcounter)
    fi

    # Calculate target year and month with proper numeric comparison for CIS
    current_year=$(date +%Y)
    current_month_num=$(echo "$thismonthnumber" | sed 's/^0*//')
    score_month_num=$(echo "$scoremonthcounter" | sed 's/^0*//')
    
    # If the score month is greater than current month, it's from last year
    if [[ $score_month_num -gt $current_month_num ]]; then
        target_year=$((current_year - 1))
    else
        target_year=$current_year
    fi
    
    # Get historical CIS score with DynamoDB fallback to Security Hub
    historical_score=$(get_historical_score_with_fallback "CIS" "$scoremonthcounter" "$target_year")
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "    "
    ((loopcounter--))
done

printf "\n"

# CIS v1.4 LOOP - PULL HISTORICAL SCORES FROM SECURITY HUB
printf "CIS v1.4 Scores:     "

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d'$scoremonthcounter)
    fi

    # Calculate target year and month with proper numeric comparison for CIS v1.4
    current_year=$(date +%Y)
    current_month_num=$(echo "$thismonthnumber" | sed 's/^0*//')
    score_month_num=$(echo "$scoremonthcounter" | sed 's/^0*//')
    
    # If the score month is greater than current month, it's from last year
    if [[ $score_month_num -gt $current_month_num ]]; then
        target_year=$((current_year - 1))
    else
        target_year=$current_year
    fi
    
    # Get historical CIS v1.4 score with DynamoDB fallback to Security Hub
    historical_score=$(get_historical_score_with_fallback "CIS14" "$scoremonthcounter" "$target_year")
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "    "
    ((loopcounter--))
done

printf "\n"

# CIS v3.0 LOOP - PULL HISTORICAL SCORES WITH COMPREHENSIVE FALLBACK
printf "CIS v3.0 Scores:     "

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d'$scoremonthcounter)
    fi

    # Calculate target year and month with proper numeric comparison for CIS v3.0
    current_year=$(date +%Y)
    current_month_num=$(echo "$thismonthnumber" | sed 's/^0*//')
    score_month_num=$(echo "$scoremonthcounter" | sed 's/^0*//')
    
    # If the score month is greater than current month, it's from last year
    if [[ $score_month_num -gt $current_month_num ]]; then
        target_year=$((current_year - 1))
    else
        target_year=$current_year
    fi
    
    # Get historical CIS v3.0 score with comprehensive fallback logic
    historical_score=$(get_historical_score_with_fallback "CIS30" "$scoremonthcounter" "$target_year")
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "    "
    ((loopcounter--))
done

printf "\n"

# PCI LOOP - PULL HISTORICAL SCORES FROM SECURITY HUB
printf "PCI Scores:          "

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d'$scoremonthcounter)
    fi

    # Calculate target year and month with proper numeric comparison for PCI
    current_year=$(date +%Y)
    current_month_num=$(echo "$thismonthnumber" | sed 's/^0*//')
    score_month_num=$(echo "$scoremonthcounter" | sed 's/^0*//')
    
    # If the score month is greater than current month, it's from last year
    if [[ $score_month_num -gt $current_month_num ]]; then
        target_year=$((current_year - 1))
    else
        target_year=$current_year
    fi
    
    # Get historical PCI score with DynamoDB fallback to Security Hub
    historical_score=$(get_historical_score_with_fallback "PCI" "$scoremonthcounter" "$target_year")
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "    "
    ((loopcounter--))
done

printf "\n"

# PCI v4 LOOP - PULL HISTORICAL SCORES FROM SECURITY HUB
printf "PCI v4 Scores:       "

scoremonthcounter=$(echo $thismonthnumber|sed 's/^0*//')
let "scoremonthcounter = scoremonthcounter - 5"
if [[ $scoremonthcounter -lt 0 ]]; then
    let "scoremonthcounter = scoremonthcounter +12"
fi

loopcounter=6
while [ $loopcounter -ge 1 ]
do
    if [[ $scoremonthcounter -le 9 ]]; then
        scoremonthcounter=$(printf '%01d'$scoremonthcounter)
    fi

    # Calculate target year and month with proper numeric comparison for PCI v4
    current_year=$(date +%Y)
    current_month_num=$(echo "$thismonthnumber" | sed 's/^0*//')
    score_month_num=$(echo "$scoremonthcounter" | sed 's/^0*//')
    
    # If the score month is greater than current month, it's from last year
    if [[ $score_month_num -gt $current_month_num ]]; then
        target_year=$((current_year - 1))
    else
        target_year=$current_year
    fi
    
    # Get historical PCI v4 score with DynamoDB fallback to Security Hub
    historical_score=$(get_historical_score_with_fallback "PCI4" "$scoremonthcounter" "$target_year")
    
    echo -n "$historical_score%"
    scoremonthcounter=$(echo $scoremonthcounter | sed 's/^0*//')
    ((scoremonthcounter++))
    if [[ $scoremonthcounter == 13 ]]; then
        let "scoremonthcounter = 01"
    fi
    echo -ne "    "
    ((loopcounter--))
done

printf "\n"
printf "  \n"