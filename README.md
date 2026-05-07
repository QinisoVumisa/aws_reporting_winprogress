# AWS Security Reporting & Compliance Tool

## Overview

An automated AWS security and compliance reporting system that generates comprehensive security reports by analyzing AWS Security Hub findings, GuardDuty incidents, and compliance framework adherence. The tool creates both text-based reports and Word documents for distribution to customers.

**Author:** Qiniso Vumisa

## Features

### Security Monitoring
- **Multi-Account Support**: Aggregates security findings across multiple AWS accounts
- **Multi-Region Monitoring**: Tracks security events across all enabled AWS regions
- **Security Hub Integration**: Comprehensive Security Hub findings analysis
- **GuardDuty Integration**: Threat detection and incident tracking
- **AWS Service Monitoring**: CloudTrail, Config, and GuardDuty status verification

### Compliance Frameworks
The tool supports multiple compliance framework versions:
- ✅ **CIS AWS Foundations Benchmark v3.0.0**
- ✅ **CIS AWS Foundations Benchmark v1.4.0**
- ✅ **CIS AWS Foundations Benchmark v1.2.0** (legacy)
- ✅ **PCI DSS v4.0.1**
- ✅ **PCI DSS v3.2.1** (legacy)
- ✅ **AWS Foundational Security Best Practices v1.0.0**

### Report Components

#### Compliance Reports
- **Compliance Scores**: Overall security posture scoring per framework
- **Critical & High Controls**: Top 5 failing critical/high severity controls
- **Recent Findings**: Recently discovered compliance issues
- **Resolved Issues**: Track remediation progress
- **Urgent Findings**: High-priority issues requiring immediate attention
- **EC2 Compliance**: Specific EC2 instance compliance tracking
- **Top 5 Failing Resources**: Most non-compliant resources
- **Suppressed Findings**: Tracked suppressed issues
- **Compliance Matrix**: Framework comparison and failure counts

#### Monitoring Reports
- **GuardDuty Incidents**: Monthly threat detection statistics
- **Security Service Status**: Verification of CloudTrail, Config, GuardDuty
- **Account Coverage**: Number of accounts and regions reporting
- **Enabled Standards**: Active compliance frameworks per account/region

## Project Structure

```
aws_reporting_winprogress/
├── report.sh                          # Main orchestration script
├── report.py                          # Word document generator
├── runcompliance.sh                   # Compliance report execution
├── runmonitoring.sh                   # Monitoring report execution
├── dynamodb.sh                        # Customer credential retrieval from DynamoDB
├── install-dependencies.sh            # Dependency installation script
├── modules/                           # Report modules
│   ├── monitoring.sh                  # Security monitoring checks
│   ├── guardduty-main.sh             # GuardDuty incident analysis
│   ├── compliance-scores.sh           # Framework scoring calculations
│   ├── compliance-matrix.sh           # Cross-framework comparison
│   ├── compliance-framework-status.sh # Detect enabled frameworks
│   ├── compliance-critical-high-controls.sh  # Critical findings
│   ├── compliance-recent.sh           # Recent compliance issues
│   ├── compliance-resolved.sh         # Resolved findings tracker
│   ├── compliance-urgent.sh           # Urgent issues
│   ├── compliance-ec2.sh             # EC2-specific compliance
│   ├── compliance-top5failingresources.sh   # Top failing resources
│   └── compliance-suppressed.sh       # Suppressed findings
├── OUTPUT/                            # Generated reports
│   └── YYYY-MM/                      # Monthly report folders
└── test-*.sh                          # Testing scripts
```

## Prerequisites

### System Requirements
- **OS**: Linux/macOS (WSL supported on Windows)
- **AWS CLI**: Configured with appropriate credentials
- **JQ**: JSON parsing utility
- **Python 3**: With pip package manager
- **Bash**: Version 4.0 or higher

### AWS Permissions
The AWS credentials used must have:
- SecurityHub read access (`securityhub:GetFindings`, `securityhub:ListMembers`)
- GuardDuty read access
- STS assume role capabilities (for multi-account scenarios)
- DynamoDB access (optional, for credential management)

### Python Dependencies
- `python-docx`: Word document generation

## Installation

### 1. Clone/Download the Repository
```bash
cd /path/to/your/workspace
```

### 2. Install Dependencies
```bash
./install-dependencies.sh
```

This will install:
- `dos2unix` (line ending conversion)
- `python3-pip` (Python package manager)
- `python-docx` (Word document library)
- `mutt` (email functionality, optional)
- `jq` (JSON processor)

### 3. Set Execute Permissions
```bash
chmod +x *.sh
chmod +x modules/*.sh
```

### 4. Prepare Word Template
Ensure you have the template file:
```
YYYY-MM - Customer Name - Monthly Security Essentials Report.docx
```

## Usage

### Quick Start

#### Option 1: Interactive Mode
```bash
./report.sh
```

The script will prompt for:
- Customer name
- Security Hub aggregate region (default: eu-west-1)

#### Option 2: Pre-configured Credentials
```bash
# Paste AWS SSO credentials into terminal
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_SESSION_TOKEN=your_session_token

# Run the report
./report.sh
```

#### Option 3: DynamoDB Customer Selection
If configured with DynamoDB customer database:
```bash
./report.sh
# Select customer from list
```

### Individual Report Components

#### Run Monitoring Report Only
```bash
./runmonitoring.sh
```

#### Run Compliance Report Only
```bash
./runcompliance.sh
```

#### Run Specific Module
```bash
./modules/compliance-scores.sh
./modules/guardduty-main.sh
```

## Configuration

### Environment Variables

```bash
export AWS_DEFAULT_REGION=eu-west-1     # Security Hub aggregate region
export AWS_RETRY_MODE=standard          # API retry behavior
export AWS_MAX_ATTEMPTS=10              # Maximum API retry attempts
export custname="Customer Name"         # Customer identifier
export today=$(date +"%Y-%m-%d")        # Report date
```

### DynamoDB Integration (Optional)

The tool can retrieve customer credentials from a DynamoDB table:

**Table Name**: `mcs-customers`

**Schema**:
```json
{
  "CustomerName": "string",
  "RemoteMonitoringRoleArn": "string",
  "SecHubRegion": "string",
  "ExternalId": "string",
  "AccessKeyId": "string (optional)",
  "SecretAccessKey": "string (optional)"
}
```

## Output

### Generated Files

Reports are saved in `OUTPUT/YYYY-MM/` directory:

1. **Text Monitoring Report**
   - Filename: `YYYY-MM-DD.customer-name.infosec-monitoring-report.txt`
   - Contains: Security service status, account/region coverage, GuardDuty stats

2. **Text Compliance Report**
   - Filename: `YYYY-MM-DD.customer-name.infosec-compliance-report.txt`
   - Contains: Compliance scores, failing controls, top issues

3. **Word Document Report**
   - Filename: `YYYY-MM - Customer Name - Monthly Security Essentials Report.docx`
   - Contains: Formatted report with tables and summaries

### Report Sections

#### Monitoring Report
```
MONITORING SECTION
- Number of AWS accounts reporting security events
- Number of AWS regions reporting security events
- Enabled compliance standards
- CloudTrail, Config, GuardDuty status

GUARDDUTY INCIDENTS SECTION
- Monthly incident counts (High, Medium, Low)
- 3-month trend analysis
- Incident details
```

#### Compliance Report
```
INFRASTRUCTURE COMPLIANCE SECTION
- Framework-specific compliance scores (%)
- Pass/fail statistics per framework

CRITICAL & HIGH SEVERITY CONTROLS
- Top 5 failing controls per framework

RECENT FINDINGS
- Newly discovered compliance issues

URGENT FINDINGS
- High-priority remediations required

TOP 5 FAILING RESOURCES
- Most non-compliant resources by framework

EC2 COMPLIANCE
- Instance-specific compliance issues
```

## Testing

### Test All Modules
```bash
./test-compliance-frameworks.sh
```

### Test Specific Components
```bash
./test-framework-status.sh      # Test framework detection
./test-framework-fix.sh         # Test framework filtering
./test-report.sh                # Test report generation
```

## AWS Service Checks

The tool verifies these AWS security services:

| Service | Control ID | Purpose |
|---------|-----------|---------|
| CloudTrail | CloudTrail.1 | Audit trail logging |
| Config | Config.1 | Configuration tracking |
| GuardDuty | GuardDuty.1 | Threat detection |

## Error Handling

The tool includes robust error handling:
- **Credential Validation**: Verifies AWS credentials before execution
- **API Retry Logic**: Automatic retry with exponential backoff
- **Framework Detection**: Graceful fallback when specific framework versions unavailable
- **Missing Data Handling**: Reports "N/A" for unavailable metrics

## Troubleshooting

### Common Issues

#### 1. "Credentials Not Found"
```bash
# Solution: Ensure AWS credentials are set
aws sts get-caller-identity
```

#### 2. "Control Enumeration Issue Detected"
- Cause: Framework not enabled or no findings in date range
- Solution: Enable the framework in Security Hub or adjust date filters

#### 3. No Output Files Generated
```bash
# Check permissions
chmod +x report.sh runcompliance.sh runmonitoring.sh

# Check OUTPUT directory exists
mkdir -p OUTPUT/$(date +%Y-%m)
```

#### 4. Python Module Errors
```bash
# Reinstall python-docx
pip3 install --upgrade python-docx
```

## Automation

### Scheduled Execution (Cron)

```bash
# Edit crontab
crontab -e

# Run monthly on the 1st at 2 AM
0 2 1 * * /path/to/aws_reporting_winprogress/report.sh
```

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
name: Monthly AWS Security Report
on:
  schedule:
    - cron: '0 2 1 * *'  # Monthly on the 1st
jobs:
  generate-report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: ./install-dependencies.sh
      - name: Generate report
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: ./report.sh
```

## Security Considerations

1. **Credential Management**: Never commit AWS credentials to version control
2. **DynamoDB Access**: Ensure proper IAM policies for DynamoDB customer table access
3. **Report Storage**: Store generated reports securely (S3 with encryption recommended)
4. **Email Security**: Configure mutt with proper authentication for email delivery
5. **Least Privilege**: Use read-only AWS permissions for reporting

## Recent Enhancements

### Framework Version Support (Latest Update)
- Added support for framework-specific version detection
- Enhanced reporting with version-specific findings
- Improved accuracy for CIS v1.4.0, CIS v3.0.0, and PCI DSS v4.0.1
- Backward compatibility maintained for legacy frameworks

See [ENHANCEMENT_SUMMARY.md](ENHANCEMENT_SUMMARY.md) for detailed changes.

## Backup & Recovery

### Create Backup
```bash
./backup.sh
```

### Restore from Backup
```bash
# Backups are stored with timestamps
# Manually restore from backup directory
```

## Contributing

When modifying the tool:
1. Test changes with `./test-*.sh` scripts
2. Ensure backward compatibility with existing reports
3. Document new features in this README
4. Update ENHANCEMENT_SUMMARY.md for significant changes

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review existing output logs in `OUTPUT/` directory
3. Verify AWS credentials and permissions
4. Test individual modules for isolation

## License

[Specify your license here]

## Changelog

### Version History
- **Latest**: Framework version-specific reporting (CIS v3.0.0, v1.4.0, PCI v4.0.1)
- **2.0**: Added DynamoDB integration for customer management
- **1.0**: Initial release with basic compliance and monitoring reports

---

**Last Updated**: May 2026
