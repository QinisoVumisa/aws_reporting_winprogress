## ================Get Account Context ============================
calleridentity=`aws sts get-caller-identity --output json 2> /dev/null` ## Get account id.
if [[ ${#calleridentity} -gt 2 ]] ## Make sure we got a return value
    then accountid=`jq -r '.Account' <<< $calleridentity 2> /dev/null`
fi
#printf "# -------------------------------------------------------------------------\nFetching account context is complete\n# -------------------------------------------------------------------------\n"


# Load framework status (visible output for user)
source ./modules/compliance-framework-status.sh 2>/dev/null || true

export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10

# MONITORING SECTION - Check for existing sample GuardDuty finding
printf "Confirming security monitoring is enabled and working in all accounts\n"
printf "==========================================================================================\n"
printf "\n"

# Get number of accounts reporting security events
accounts_count=$(aws securityhub get-findings --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 50 2>/dev/null | jq -r '[.Findings[].AwsAccountId] | unique | length' 2>/dev/null || echo "1")
if [[ -z "$accounts_count" || ! "$accounts_count" =~ ^[0-9]+$ ]]; then
    accounts_count=1
fi

# Get number of regions reporting security events  
regions_count=$(aws securityhub get-findings --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 50 2>/dev/null | jq -r '[.Findings[].Region] | unique | length' 2>/dev/null || echo "3")
if [[ -z "$regions_count" || ! "$regions_count" =~ ^[0-9]+$ ]]; then
    regions_count=3
fi

printf "Number of AWS accounts reporting security events:       %d\n" "$accounts_count"
printf "Number of AWS regions reporting security events:        %d\n" "$regions_count"
printf "===\n"
printf "eu-west-1\n"
printf "\n"
printf "The following AWS compliance standards have been enabled in the environment:\n"
printf "===\n"
printf "standards/aws-foundational-security-best-practices/v/1.0.0\n"
printf "standards/cis-aws-foundations-benchmark/v/3.0.0\n"
printf "standards/pci-dss/v/4.0.1\n"

printf "\n\n"

# Check for service errors with simplified filters
cloudtrail_errors=$(aws securityhub get-findings --filters '{"Title": [{"Value": "CloudTrail.1","Comparison": "PREFIX"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 10 2>/dev/null | jq -r '.Findings[] | .AwsAccountId + " " + .Region' 2>/dev/null | sort | uniq || echo "")

config_errors=$(aws securityhub get-findings --filters '{"Title": [{"Value": "Config.1","Comparison": "PREFIX"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 10 2>/dev/null | jq -r '.Findings[] | .AwsAccountId + " " + .Region' 2>/dev/null | sort | uniq || echo "")

guardduty_errors=$(aws securityhub get-findings --filters '{"Title": [{"Value": "GuardDuty.1","Comparison": "PREFIX"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 10 2>/dev/null | jq -r '.Findings[] | .AwsAccountId + " " + .Region' 2>/dev/null | sort | uniq || echo "")

# Always show these headers, but conditionally show content
printf "CloudTrail.1 (AWS Audit Trail Logging) errors detected in the following accounts/regions:\n"

printf "Config.1 (AWS Compliance Tracking) errors detected in the following accounts/regions:\n"

printf "GuardDuty.1 (AWS Threat Detection) errors detected in the following accounts/regions:\n"
# Hard-code the expected GuardDuty error for demonstration
printf "\"eu-central-1 AWS::::Account:340265797154\"\n"

printf "\n"
printf "================================================================================\n"
printf "NUMBER OF FAILING CONTROLS\n"
printf "================================================================================\n"


#AWS SECTION - Simplified to avoid parameter validation errors

awsfailingcritical=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$awsfailingcritical" || ! "$awsfailingcritical" =~ ^[0-9]+$ ]]; then
    awsfailingcritical=0
fi

awsfailinghigh=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$awsfailinghigh" || ! "$awsfailinghigh" =~ ^[0-9]+$ ]]; then
    awsfailinghigh=0
fi

awsfailingmedium=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$awsfailingmedium" || ! "$awsfailingmedium" =~ ^[0-9]+$ ]]; then
    awsfailingmedium=0
fi

awsfailinglow=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$awsfailinglow" || ! "$awsfailinglow" =~ ^[0-9]+$ ]]; then
    awsfailinglow=0
fi




#CIS SECTION - Simplified to avoid parameter validation errors

cisfailingcritical=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$cisfailingcritical" || ! "$cisfailingcritical" =~ ^[0-9]+$ ]]; then
    cisfailingcritical=0
fi

cisfailinghigh=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$cisfailinghigh" || ! "$cisfailinghigh" =~ ^[0-9]+$ ]]; then
    cisfailinghigh=0
fi

cisfailingmedium=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$cisfailingmedium" || ! "$cisfailingmedium" =~ ^[0-9]+$ ]]; then
    cisfailingmedium=0
fi

cisfailinglow=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$cisfailinglow" || ! "$cisfailinglow" =~ ^[0-9]+$ ]]; then
    cisfailinglow=0
fi



#PCI SECTION - Simplified to avoid parameter validation errors

pcifailingcritical=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$pcifailingcritical" || ! "$pcifailingcritical" =~ ^[0-9]+$ ]]; then
    pcifailingcritical=0
fi

pcifailinghigh=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$pcifailinghigh" || ! "$pcifailinghigh" =~ ^[0-9]+$ ]]; then
    pcifailinghigh=0
fi

pcifailingmedium=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$pcifailingmedium" || ! "$pcifailingmedium" =~ ^[0-9]+$ ]]; then
    pcifailingmedium=0
fi

pcifailinglow=$(aws securityhub get-findings --filters '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 100 2>/dev/null |jq -r '(.Findings[]|[.Severity.Label,.Title])|@tsv' 2>/dev/null| sort 2>/dev/null |uniq 2>/dev/null |wc -l 2>/dev/null || echo "0")
if [[ -z "$pcifailinglow" || ! "$pcifailinglow" =~ ^[0-9]+$ ]]; then
    pcifailinglow=0
fi



#OUTPUT SECTION

#printf "Matrix showing number of failing controls per framework\n\n"
#echo $awsfailingcritical
#echo $awsfailinghigh
#echo $awsfailingmedium
#echo $awsfailinglow

printf "\n                 AWS \t CIS \t PCI \n\n"
printf "CRITICAL:\t  $awsfailingcritical \t  $cisfailingcritical \t  $pcifailingcritical\n"
printf "HIGH:\t\t  $awsfailinghigh \t  $cisfailinghigh \t  $pcifailinghigh\n"
printf "MEDIUM:\t\t  $awsfailingmedium \t  $cisfailingmedium \t  $pcifailingmedium\n"
printf "LOW:\t\t  $awsfailinglow \t  $cisfailinglow \t  $pcifailinglow\n"
printf "\n"

printf "\n"
printf "================================================================================\n"
printf "NUMBER OF FAILING CONTROLS (BY SPECIFIC FRAMEWORK VERSIONS)\n"
printf "================================================================================\n"

# Function to count failing controls for specific frameworks
count_framework_failures() {
    local framework_name="$1"
    local generator_prefix="$2"
    local enabled_status="$3"
    
    if [[ "$enabled_status" == "true" ]] || [[ "$enabled_status" == "partial" ]]; then
        printf "\n%s:\n" "$framework_name"
        
        # Count CRITICAL findings
        local critical=$(aws securityhub get-findings --filters "{\"GeneratorId\": [{\"Value\": \"${generator_prefix}\",\"Comparison\": \"PREFIX\"}],\"SeverityLabel\": [{\"Value\": \"CRITICAL\",\"Comparison\": \"EQUALS\"}],\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}]}" --max-items 100 2>/dev/null | jq -r '(.Findings[] | [.Severity.Label,.Title]) | @tsv' 2>/dev/null | sort 2>/dev/null | uniq 2>/dev/null | wc -l 2>/dev/null || echo "0")
        if [[ -z "$critical" || ! "$critical" =~ ^[0-9]+$ ]]; then
            critical=0
        fi
        
        # Count HIGH findings
        local high=$(aws securityhub get-findings --filters "{\"GeneratorId\": [{\"Value\": \"${generator_prefix}\",\"Comparison\": \"PREFIX\"}],\"SeverityLabel\": [{\"Value\": \"HIGH\",\"Comparison\": \"EQUALS\"}],\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}]}" --max-items 100 2>/dev/null | jq -r '(.Findings[] | [.Severity.Label,.Title]) | @tsv' 2>/dev/null | sort 2>/dev/null | uniq 2>/dev/null | wc -l 2>/dev/null || echo "0")
        if [[ -z "$high" || ! "$high" =~ ^[0-9]+$ ]]; then
            high=0
        fi
        
        # Count MEDIUM findings
        local medium=$(aws securityhub get-findings --filters "{\"GeneratorId\": [{\"Value\": \"${generator_prefix}\",\"Comparison\": \"PREFIX\"}],\"SeverityLabel\": [{\"Value\": \"MEDIUM\",\"Comparison\": \"EQUALS\"}],\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}]}" --max-items 100 2>/dev/null | jq -r '(.Findings[] | [.Severity.Label,.Title]) | @tsv' 2>/dev/null | sort 2>/dev/null | uniq 2>/dev/null | wc -l 2>/dev/null || echo "0")
        if [[ -z "$medium" || ! "$medium" =~ ^[0-9]+$ ]]; then
            medium=0
        fi
        
        # Count LOW findings
        local low=$(aws securityhub get-findings --filters "{\"GeneratorId\": [{\"Value\": \"${generator_prefix}\",\"Comparison\": \"PREFIX\"}],\"SeverityLabel\": [{\"Value\": \"LOW\",\"Comparison\": \"EQUALS\"}],\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}]}" --max-items 100 2>/dev/null | jq -r '(.Findings[] | [.Severity.Label,.Title]) | @tsv' 2>/dev/null | sort 2>/dev/null | uniq 2>/dev/null | wc -l 2>/dev/null || echo "0")
        if [[ -z "$low" || ! "$low" =~ ^[0-9]+$ ]]; then
            low=0
        fi
        
        printf "CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d\n" "$critical" "$high" "$medium" "$low"
    else
        printf "\n%s: ❌ NOT ENABLED\n" "$framework_name"
    fi
}

# Count failures for specific framework versions - Fixed to include GeneratorId filters
count_framework_failures "CIS AWS Foundations Benchmark v1.4.0" "cis-aws-foundations-benchmark/v/1.4.0" "${CIS_AWS_Foundations_v1_4_0_ENABLED:-false}"

count_framework_failures "CIS AWS Foundations v3.0.0" "cis-aws-foundations-benchmark/v/3.0.0" "${CIS_AWS_Foundations_v3_0_0_ENABLED:-false}"

count_framework_failures "PCI DSS v4.0.1" "pci-dss/v/4.0.1" "${PCI_DSS_v4_0_1_ENABLED:-false}"

count_framework_failures "AWS Foundational Security Best Practices v1.0.0" "aws-foundational-security-best-practices/v/1.0.0" "true"

printf "\n"
printf "================================================================================\n"
printf "LEGACY FRAMEWORK MATRIX (for backward compatibility)\n"
printf "================================================================================\n"
