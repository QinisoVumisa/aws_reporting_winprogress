### Created by: Qiniso Vumisa ###

##################################################################################
# Libraries that are required for the customer report to be generated.
##################################################################################
import sys
import subprocess
from docx import Document
from datetime import datetime, timedelta
from docx.shared import Pt
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT

# The customer name
customer_name = sys.argv[1]

# Function to run the bash script
def execute_shell_script(script_path):
    process = subprocess.Popen(['bash', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, _ = process.communicate()
    return stdout


# The date formats to be used throughout the report
back_track_days = datetime.now() - timedelta(days=15)
full_date = back_track_days.strftime('%B %Y') # Month Year - For Title Page
date = datetime.now().strftime('%Y-%m') # YYYY-MM - For File Name

# The name of the report when it is done
report_name = f'{date} - {customer_name} - Monthly Security Essentials Report.docx'

print(f"Generating '{report_name}'.\n")

# Open the template
doc = Document('YYYY-MM - Customer Name - Monthly Security Essentials Report.docx')

# Define font settings
font_name = 'Calibri'
font_size = Pt(12)

# Line spacing
next_line = ""

# Set default font for the entire document
doc.styles['Normal'].font.name = font_name
doc.styles['Normal'].font.size = font_size

# Add the title to the Title Property
title_property = doc.core_properties.title
doc.core_properties.title = f"Security Essentials: {customer_name}"
title_property = doc.core_properties.subject
doc.core_properties.subject = "Monthly Compliance Report"

# Add the date to the Publish Date property
date_property = doc.core_properties.comments
doc.core_properties.comments = f"For the period ending {full_date}"

# Security Monitoring Compliance Section
doc.add_heading('Security Monitoring Compliance', level=1)

shell_script_path = "./modules/monitoring.sh"
monitoring_content = execute_shell_script(shell_script_path)
doc.add_paragraph("\nConfirming security monitoring is enabled and working in all accounts.\n")
monitoring_table_content = monitoring_content.strip().split("==========================================================================================\nMONITORING SECTION\n-\nConfirming security monitoring is enabled and working in all accounts\n==========================================================================================")

# Create the table with headings
monitoring_table_1 = doc.add_table(rows=1, cols=2)
monitoring_table_1.style = 'Accented_Table_Header'

# Set the column headers
headers_1 = ['AWS Security Service']
for col_num_1, header_text_1 in enumerate(headers_1):
    cell_1 = monitoring_table_1.cell(0, col_num_1)
    cell_1.text = header_text_1
    cell_1.paragraphs[0].runs[0].bold = True
    cell_1.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

    for content in monitoring_table_content:
        stripped_content = content.strip().split("\n\n")
    
    sections = stripped_content[0].strip().split("===")

    # for section in sections:
    line_1 = sections[0].strip().split("\n")
    for line in line_1:
        key_1, value_1 = line.split(":")
        key_1_1 = key_1.lstrip("Number of ")
        # Add data rows
        row_cells_1 = monitoring_table_1.add_row().cells
        row_cells_1[0].text = key_1_1
        row_cells_1[1].text = value_1.lstrip()  
    break
# Adjust column widths
monitoring_table_1.autofit = True

doc.add_paragraph(next_line)
    
# Create the table with headings
monitoring_table_2 = doc.add_table(rows=1, cols=1)
monitoring_table_2.style = 'Accented_Table_Header'

# Set the column headers
headers_2 = ['Active region(s)']
for col_num_2, header_text_2 in enumerate(headers_2):
    cell_2 = monitoring_table_2.cell(0, col_num_2)
    cell_2.text = header_text_2
    cell_2.paragraphs[0].runs[0].bold = True
    cell_2.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

    for content in monitoring_table_content:
        stripped_content = content.strip().split("\n\n")
    
    sections = stripped_content[0].strip().split("===")
   
    line_2 = sections[1].strip().split("\n")
    for line in line_2:
        # Add data rows
        row_cells_2 = monitoring_table_2.add_row().cells
        row_cells_2[0].text = line
    break
# Adjust column widths
monitoring_table_2.autofit = True

doc.add_paragraph(next_line)

# Create the table with headings
monitoring_table_3 = doc.add_table(rows=1, cols=1)
monitoring_table_3.style = 'Accented_Table_Header'

# Set the column headers
headers_3 = ['The following AWS compliance standards have been enabled in the environment:']
for col_num_3, header_text_3 in enumerate(headers_3):
    cell_3 = monitoring_table_3.cell(0, col_num_3)
    cell_3.text = header_text_3
    cell_3.paragraphs[0].runs[0].bold = True
    cell_3.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

    for content in monitoring_table_content:
        stripped_content = content.strip().split("\n\n")
    
    sections = stripped_content[1].strip().split("===")
      
    # for section in sections:
    line_3 = sections[1].strip().split("\n")
    for line in line_3:
        # Add data rows
        row_cells_3 = monitoring_table_3.add_row().cells
        row_cells_3[0].text = line
    break
# Adjust column widths
monitoring_table_3.autofit = True

doc.add_paragraph(next_line)

# GuardDuty – Security Threats Detected Section
doc.add_heading('GuardDuty - Security Threats Detected', level=1)

shell_script_path = "./modules/guardduty-main.sh"
guardduty_content = execute_shell_script(shell_script_path)
doc.add_paragraph("\nAWS GuardDuty is a threat detection service which monitors all network flows, audit logs, DNS lookups and S3 bucket actions for anomalous activity which could be indicators of compromise or provide warning of attempted infiltration.\n")
guardduty_table_content = guardduty_content.strip().split("================================================================================\nGUARDDUTY INCIDENTS SECTION\n-\nGuardDuty detects anomalous activity in the environment\n================================================================================")

# Create the table with headings
guardduty_table_1 = doc.add_table(rows=1, cols=4)
guardduty_table_1.style = 'Accented_Table_Total_Row'

for content in guardduty_table_content:
        stripped_content = content.strip().split("\n\n")

headers_4 = stripped_content[0].strip().split("\t")

# Add headers to the table
for col_num_4, header_text_4 in enumerate(headers_4):
    cell_4 = guardduty_table_1.cell(0, col_num_4)
    cell_4.text = header_text_4
    cell_4.paragraphs[0].runs[0].bold = True
    
values_4 = stripped_content[1].strip().split("\n")

# Add values to the table
for low_value in values_4:
    stripped_values = low_value.strip().split("\t\t\t\t")
    row_cells_4 = guardduty_table_1.add_row().cells
    row_values_1 = stripped_values[0].strip(":").split()
    row_values_2 = stripped_values[1].strip("\t ").split()
    
    for col_num_4, cell_value in enumerate(row_values_1):
        # Add the column headers
        row_cells_4[col_num_4].text = cell_value
        row_cells_4[col_num_4].paragraphs[0].runs[0].bold = True
        for row_num, row_cell_value in enumerate(row_values_2):
            row_num += 1
            # Add row data
            row_cells_4[row_num].text = row_cell_value
            if row_num == 4:
                row_cells_4[row_num].paragraphs[0].runs[0].bold = True
# Adjust column widths
guardduty_table_1.autofit = True

doc.add_paragraph(next_line)

# Create the table with headings
guardduty_table_high = doc.add_table(rows=2, cols=1)
guardduty_table_high.style = 'Accented_Table_Header'

# Set the headers
header_high = ['HIGH GUARDDUTY FINDINGS', 'Finding(s)']
for row_num_high, header_text_high in enumerate(header_high):
    cell_high = guardduty_table_high.cell(0, row_num_high)
    cell_high.text = header_text_high
    cell_high.paragraphs[0].runs[0].bold = True
    cell_high.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

# Add the row data
high_data = stripped_content[3].lstrip("HIGH\n").split("====")
high_finding_data = {}

for high_content in high_data:
    high_findings = high_content.strip().split("]\n[")
    for high_finding in high_findings:
        stripped_high_finding = ((high_finding.lstrip("[")).rstrip("]")).lstrip("\n ").split(",")
        if len(stripped_high_finding) > 1:
            high_key = stripped_high_finding[3].lstrip("\n ")
            high_value = stripped_high_finding[2].lstrip("\n ")
            high_substring = stripped_high_finding[1].lstrip("\n ")

            if high_key not in high_finding_data:
                high_finding_data[high_key] = {high_value: [high_substring]}
            elif high_value not in high_finding_data[high_key]:
                high_finding_data[high_key][high_value] = [high_substring]
            else:
                high_finding_data[high_key][high_value].append(high_substring)
        else:
            break
    if high_finding_data:
        for high_type, high_details in high_finding_data.items():
            for high_resource, high_id in high_details.items():
                row_cells_high = guardduty_table_high.add_row().cells
                row_cells_high[0].text = f"{len(high_id)} X {high_type}\n\t{high_resource}\n\t{high_id}"
    else:
        continue
# Adjust column widths
guardduty_table_high.autofit = True

doc.add_paragraph(next_line)

# Create the table with headings
guardduty_table_med = doc.add_table(rows=2, cols=1)
guardduty_table_med.style = 'Accented_Table_Header'

# Set the headers
header_med = ['MEDIUM GUARDDUTY FINDINGS', 'Finding(s)']
for row_num_med, header_text_med in enumerate(header_med):
    cell_med = guardduty_table_med.cell(0, row_num_med)
    cell_med.text = header_text_med
    cell_med.paragraphs[0].runs[0].bold = True
    cell_med.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

# Add the row data
med_data = stripped_content[4].lstrip("MEDIUM\n").split("======")
med_finding_data = {}

for med_content in med_data:
    med_findings = med_content.strip().split("]\n[")
    for med_finding in med_findings:
        stripped_med_finding = ((med_finding.lstrip("[")).rstrip("]")).lstrip("\n ").split(",")
        if len(stripped_med_finding) > 1:
            med_key = stripped_med_finding[3].lstrip("\n ")
            med_value = stripped_med_finding[2].lstrip("\n ")
            med_substring = stripped_med_finding[1].lstrip("\n ")

            if med_key not in med_finding_data:
                med_finding_data[med_key] = {med_value: [med_substring]}
            elif med_value not in med_finding_data[med_key]:
                med_finding_data[med_key][med_value] = [med_substring]
            else:
                med_finding_data[med_key][med_value].append(med_substring)
        else:
            break
    if med_finding_data:
        for med_type, med_details in med_finding_data.items():
            for med_resource, med_id in med_details.items():
                row_cells_med = guardduty_table_med.add_row().cells
                row_cells_med[0].text = f"{len(med_id)} X {med_type}\n\t{med_resource}\n\t{med_id}"
    else:
        continue
# Adjust column widths
guardduty_table_med.autofit = True

doc.add_paragraph(next_line)

# Create the table with headings
guardduty_table_low = doc.add_table(rows=2, cols=1)
guardduty_table_low.style = 'Accented_Table_Header'

# Set the headers
header_low = ['LOW GUARDDUTY FINDINGS', 'Finding(s)']
for row_num_low, header_text_low in enumerate(header_low):
    cell_low = guardduty_table_low.cell(0, row_num_low)
    cell_low.text = header_text_low
    cell_low.paragraphs[0].runs[0].bold = True
    cell_low.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

# Add the row data
low_data = stripped_content[5].lstrip("LOW\n").split("===")
low_finding_data = {}

for low_content in low_data:
    low_findings = low_content.strip().split("]\n[")
    for low_finding in low_findings:
        stripped_low_finding = ((low_finding.lstrip("[")).rstrip("]")).lstrip("\n ").split(",")
        if len(stripped_low_finding) > 1:
            low_key = stripped_low_finding[3].lstrip("\n ")
            low_value = stripped_low_finding[2].lstrip("\n ")
            low_substring = stripped_low_finding[1].lstrip("\n ")

            if low_key not in low_finding_data:
                low_finding_data[low_key] = {low_value: [low_substring]}
            elif low_value not in low_finding_data[low_key]:
                low_finding_data[low_key][low_value] = [low_substring]
            else:
                low_finding_data[low_key][low_value].append(low_substring)
        else:
            break
    if low_finding_data:
        for low_type, low_details in low_finding_data.items():
            for low_resource, low_id in low_details.items():
                row_cells_low = guardduty_table_low.add_row().cells
                row_cells_low[0].text = f"{len(low_id)} X {low_type}\n\t{low_resource}\n\t{low_id}"
    else:
        continue
# Adjust column widths
guardduty_table_low.autofit = True
        
doc.add_paragraph(next_line)

# AWS Infrastructure Compliance Section
doc.add_heading('AWS Infrastructure Compliance', level=1)

shell_script_path = "./modules/compliance-scores.sh"
scores_content = execute_shell_script(shell_script_path)
doc.add_paragraph(f"\nAs you will also note from the scores, there is a (some / no) movement in the score indicating (improvement / consitency) but there is still room for more. Resulting in an overall score of <score>% across all standards (last month it was <score>%).\n")
scores_table_content = scores_content.strip().split("\n\nHistorical scores per framework as recorded in monthly report. (NULL = Score not yet saved in DB)\n===========================================================================\n")

split_score_content = scores_table_content[1].strip().split("\n\n")

score_headers = split_score_content[0].strip().split("\t\t")
score_header_data = score_headers[1].strip().split("\t")

score_headers_content = []
score_data_content = []

score_headers_content.append(score_headers[0])

for header in score_header_data:
    score_headers_content.append(header)

score_data = split_score_content[1].strip().split("\n")

for score_data_row in score_data:
    score_data_content.append(score_data_row.strip().split("\t"))

# Create the table with headings
scores_table = doc.add_table(rows=1, cols=8)
scores_table.style = 'Accented_Table_Header_Column'
    
# Set the headers
for col_num_5, score_header_text in enumerate(score_headers_content):
    cell_score_header = scores_table.cell(0, col_num_5)
    cell_score_header.text = score_header_text
    cell_score_header.paragraphs[0].runs[0].bold = True

# Add the row data 
for score_row, score_data_text in enumerate(score_data_content):
    cell_score_data = scores_table.add_row().cells
    score_row+=1
    for col_num_6, score_row_data in enumerate(score_data_text):
        cell_score_data = scores_table.cell(score_row, col_num_6)
        cell_score_data.text = score_row_data
        if col_num_6 == 5:
            previous_score = score_row_data.rstrip("%")
        if col_num_6 == 6:
            current_score = score_row_data.rstrip("%")
        if col_num_6 == 6:
            col_num_6+=1
            if col_num_6 == 7:
                if current_score == "null" or previous_score == "null" or not current_score or not previous_score:
                    remark = f"No score data"
                elif int(current_score) > int(previous_score):
                    remark = f"{int(current_score) - int(previous_score)}% increase in the score for the past month"
                elif int(current_score) < int(previous_score):
                    remark = f"{int(previous_score) - int(current_score)}% decrease in the score for the past month"
                elif int(current_score) == int(previous_score):
                    remark = f"Score has remained consistent"
                cell_score_data = scores_table.cell(score_row, col_num_6)
                cell_score_data.text = remark
        if col_num_6 == 0:
            cell_score_data.paragraphs[0].runs[0].bold = True
# Adjust column widths
scores_table.autofit = True

doc.add_paragraph(next_line)

# Score Boosters - Issues Resolved in the last 30 days Section
doc.add_heading('Score Boosters - Issues Resolved in the last 30 days', level=1)
doc.add_paragraph(next_line)

shell_script_path = "./modules/compliance-resolved.sh"
resolved_content = execute_shell_script(shell_script_path)
resolved_table_content = resolved_content.strip().split("\n\n")

# Create the table with headings
resolved_table = doc.add_table(rows=1, cols=2)
resolved_table.style = 'Accented_Table_Header_Column'

# Set the column headers
resolved_headers = ['Framework', 'Control']
for col_num_7, resolved_header_text in enumerate(resolved_headers):
    cell_resolved = resolved_table.cell(0, col_num_7)
    cell_resolved.text = resolved_header_text
    cell_resolved.paragraphs[0].runs[0].bold = True

# Add the row data   
aws_resolved = resolved_table_content[1].strip().split("INFORMATIONAL")
aws_resolved_data = aws_resolved.remove(aws_resolved[0])
cis_resolved = resolved_table_content[2].strip().split("INFORMATIONAL")
cis_resolved_data = cis_resolved.remove(cis_resolved[0])
pci_resolved = resolved_table_content[3].strip().split("INFORMATIONAL")
pci_resolved_data = pci_resolved.remove(pci_resolved[0])

for aws in aws_resolved:
    if aws:
        value_aws = aws.lstrip()
        key_aws = "AWS"
        # Add data rows
        row_cells_resolved = resolved_table.add_row().cells
        row_cells_resolved[0].text = key_aws
        row_cells_resolved[0].paragraphs[0].runs[0].bold = True
        row_cells_resolved[1].text = value_aws.strip("\n")
    else:
        break

for cis in cis_resolved:
    if cis:
        value_cis = cis.lstrip()
        key_cis = "CIS"
        # Add data rows
        row_cells_resolved = resolved_table.add_row().cells
        row_cells_resolved[0].text = key_cis
        row_cells_resolved[0].paragraphs[0].runs[0].bold = True
        row_cells_resolved[1].text = value_cis.strip("\n")
    else:
        break
        
for pci in pci_resolved:
    if pci:
        value_pci = pci.lstrip()
        key_pci = "PCI"
        # Add data rows
        row_cells_resolved = resolved_table.add_row().cells
        row_cells_resolved[0].text = key_pci
        row_cells_resolved[0].paragraphs[0].runs[0].bold = True
        row_cells_resolved[1].text = value_pci.strip("\n")
    else:
        break
# Adjust column widths
resolved_table.autofit = True

doc.add_paragraph(next_line)

# Score Droppers - Compliance Issues from the last 30 days Section
doc.add_heading('Score Droppers - Compliance Issues from the last 30 days', level=1)
doc.add_paragraph(next_line)

shell_script_path = "./modules/compliance-recent.sh"
recent_content = execute_shell_script(shell_script_path)
recent_table_content = recent_content.strip().split("\n\n")

aws_recent = recent_table_content[1].strip().split("\n")
aws_recent_data = aws_recent.remove(aws_recent[0])
aws_recent_data = aws_recent.remove(aws_recent[0])
cis_recent = recent_table_content[2].strip().split("\n")
cis_recent_data = cis_recent.remove(cis_recent[0])
cis_recent_data = cis_recent.remove(cis_recent[0])
pci_recent = recent_table_content[3].strip().split("\n")
pci_recent_data = pci_recent.remove(pci_recent[0])
pci_recent_data = pci_recent.remove(pci_recent[0])

aws_recent_split = {}
cis_recent_split = {}
pci_recent_split = {}

# AWS Recent
aws_count = 0
aws_split = []
while aws_count < len(aws_recent):
    aws = str(aws_recent[aws_count])
    aws_split = aws.split("  ")
    aws_item = []
    
    for item in aws_split:
        if len(item) != 0:
            aws_item.append(item)
    
    if len(aws_item) == 3:
        aws_severity = aws_item[0].rstrip()  # Extract the severity
        aws_control_name = aws_item[1].rstrip()  # Extract the control name
        aws_arn = aws_item[2].lstrip()  # Extract the ARN
        
        if aws_severity not in aws_recent_split:
            aws_recent_split[aws_severity] = {}
        if aws_control_name not in aws_recent_split[aws_severity]:
            aws_recent_split[aws_severity][aws_control_name] = []
        
        aws_recent_split[aws_severity][aws_control_name].append(aws_arn)
        aws_count += 1
    else:
        aws_count += 1  

# CIS Recent
cis_count = 0
cis_split = []
while cis_count < len(cis_recent):
    cis = str(cis_recent[cis_count])
    cis_split = cis.split("  ")
    cis_item = []
    
    for item in cis_split:
        if len(item) != 0:
            cis_item.append(item)
    
    if len(cis_item) == 3:
        cis_severity = cis_item[0].rstrip()  # Extract the severity
        cis_control_name = cis_item[1].rstrip()  # Extract the control name
        cis_arn = cis_item[2].lstrip()  # Extract the ARN
        
        if cis_severity not in cis_recent_split:
            cis_recent_split[cis_severity] = {}
        if cis_control_name not in cis_recent_split[cis_severity]:
            cis_recent_split[cis_severity][cis_control_name] = []
        
        cis_recent_split[cis_severity][cis_control_name].append(cis_arn)
        cis_count += 1
    else:
        cis_count += 1  

# PCI Recent
pci_count = 0
pci_split = []
while pci_count < len(pci_recent):
    pci = str(pci_recent[pci_count])
    pci_split = pci.split("  ")
    pci_item = []
    
    for item in pci_split:
        if len(item) != 0:
            pci_item.append(item)
    
    if len(pci_item) == 3:
        pci_severity = pci_item[0].rstrip()  # Extract the severity
        pci_control_name = pci_item[1].rstrip()  # Extract the control name
        pci_arn = pci_item[2].lstrip()  # Extract the ARN
        
        if pci_severity not in pci_recent_split:
            pci_recent_split[pci_severity] = {}
        if pci_control_name not in pci_recent_split[pci_severity]:
            pci_recent_split[pci_severity][pci_control_name] = []
        
        pci_recent_split[pci_severity][pci_control_name].append(pci_arn)
        pci_count += 1
    else:
        pci_count += 1  

def create_table_with_header(doc, style, headers, header_alignment=WD_PARAGRAPH_ALIGNMENT.LEFT, autofit=True):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = style
    for i, header in enumerate(headers):
        cell = table.cell(0, i)
        cell.text = header
        cell.paragraphs[0].runs[0].bold = True
        cell.alignment = header_alignment
    table.autofit = autofit
    return table

def add_data_rows(table, data):
    for row_data in data:
        row_cells = table.add_row().cells
        for i, cell_data in enumerate(row_data):
            row_cells[i].text = cell_data

# Create the main header table
aws_recent_main_header_table = create_table_with_header(doc, 'Accented_Table_Header', ['AWS'], WD_PARAGRAPH_ALIGNMENT.CENTER)
for severity, controls in aws_recent_split.items():
    # Create the severity header table
    severity_table = create_table_with_header(doc, 'Accented_Table_Header_Column', ['Severity', severity], WD_PARAGRAPH_ALIGNMENT.LEFT)
    for control_name, arns in controls.items():
        # Create the control header table
        control_table = create_table_with_header(doc, 'Accented_Table_Column', ['Control', control_name], WD_PARAGRAPH_ALIGNMENT.LEFT)
        control_table.cell(0, 1).paragraphs[0].runs[0].italic = True
        # Create the resource header table
        resource_table = create_table_with_header(doc, 'Accented_Table_Header', ['Resource ID(s)'], WD_PARAGRAPH_ALIGNMENT.CENTER)
        # Add data rows for resource ARNs
        add_data_rows(resource_table, [[arn] for arn in arns])
doc.add_paragraph(next_line)

# Create the main header table
cis_recent_main_header_table = create_table_with_header(doc, 'Accented_Table_Header', ['CIS'], WD_PARAGRAPH_ALIGNMENT.CENTER)
for severity, controls in cis_recent_split.items():
    # Create the severity header table
    severity_table = create_table_with_header(doc, 'Accented_Table_Header_Column', ['Severity', severity], WD_PARAGRAPH_ALIGNMENT.LEFT)
    for control_name, arns in controls.items():
        # Create the control header table
        control_table = create_table_with_header(doc, 'Accented_Table_Column', ['Control', control_name], WD_PARAGRAPH_ALIGNMENT.LEFT)
        control_table.cell(0, 1).paragraphs[0].runs[0].italic = True
        # Create the resource header table
        resource_table = create_table_with_header(doc, 'Accented_Table_Header', ['Resource ID(s)'], WD_PARAGRAPH_ALIGNMENT.CENTER)
        # Add data rows for resource ARNs
        add_data_rows(resource_table, [[arn] for arn in arns])
doc.add_paragraph(next_line)

# Create the main header table
pci_recent_main_header_table = create_table_with_header(doc, 'Accented_Table_Header', ['PCI'], WD_PARAGRAPH_ALIGNMENT.CENTER)
for severity, controls in pci_recent_split.items():
    # Create the severity header table
    severity_table = create_table_with_header(doc, 'Accented_Table_Header_Column', ['Severity', severity], WD_PARAGRAPH_ALIGNMENT.LEFT)
    for control_name, arns in controls.items():
        # Create the control header table
        control_table = create_table_with_header(doc, 'Accented_Table_Column', ['Control', control_name], WD_PARAGRAPH_ALIGNMENT.LEFT)
        control_table.cell(0, 1).paragraphs[0].runs[0].italic = True
        # Create the resource header table
        resource_table = create_table_with_header(doc, 'Accented_Table_Header', ['Resource ID(s)'], WD_PARAGRAPH_ALIGNMENT.CENTER)
        # Add data rows for resource ARNs
        add_data_rows(resource_table, [[arn] for arn in arns])
doc.add_paragraph(next_line)

# Top Five failing compliance controls per framework Section
doc.add_heading('Top Five failing compliance controls per framework', level=1)
doc.add_paragraph(next_line)

shell_script_path = "./modules/compliance-top5failingresources.sh"
top_5_content = execute_shell_script(shell_script_path)
top_5_table_content = top_5_content.strip().split("================================================================================")
frameworks = top_5_table_content[2].strip("=============").split("=============\n")
stripper = frameworks.remove(frameworks[0])

top_5 = {frameworks[0].rstrip(" Framework\n"): (frameworks[1].lstrip("\n\n").split("\n\n\n") if frameworks[1].lstrip("\n\n").split("\n\n\n") != [] else ["Enumeration error."]) if len(frameworks) > 1 else ["Enumeration error."], frameworks[2].rstrip(" Framework\n"): (frameworks[3].lstrip("\n\n").split("\n\n\n") if frameworks[3].lstrip("\n\n").split("\n\n\n") != [] else ["Enumeration error."]) if len(frameworks) > 3 else ["Enumeration error."], frameworks[4].rstrip(" Framework\n"): (frameworks[5].lstrip("\n\n").split("\n\n\n") if frameworks[5].lstrip("\n\n").split("\n\n\n") != [] else ["Enumeration error."]) if len(frameworks) > 5 else ["Enumeration error."]}

for framework, failing in top_5.items():
    compliance_framework = f"{framework} Control"
    # Create the table with headings
    top_5_table = doc.add_table(rows=1, cols=2)
    top_5_table.style = 'Accented_Table_Header'
    # Set headers
    cell_top_5_control_header = top_5_table.cell(0, 0)
    cell_top_5_control_header.text = 'Severity'
    cell_top_5_control_header.paragraphs[0].runs[0].bold = True
    cell_top_5_severity_header = top_5_table.cell(0, 1)
    cell_top_5_severity_header.text = compliance_framework
    cell_top_5_severity_header.paragraphs[0].runs[0].bold = True
    for compliance_fail in failing:
        if "Enumeration error." not in compliance_fail:
            failure = compliance_fail.split("\t\t")
            severity = failure[0]
            description = failure[1].split("===")
            # Add data rows
            row_cells_top_5 = top_5_table.add_row().cells
            row_cells_top_5[0].text = (severity.lstrip()).rstrip()
            row_cells_top_5[1].text = (description[0].lstrip()).rstrip()
        else:
            # Add data rows
            row_cells_top_5 = top_5_table.add_row().cells
            row_cells_top_5[0].text = compliance_fail
            row_cells_top_5[1].text = compliance_fail
    top_5_table.autofit = True    
    doc.add_paragraph(next_line)

#	Recommended actions Section
doc.add_heading('Recommended actions', level=1)
doc.add_paragraph(next_line)

# Save the document
doc.save(f"./OUTPUT/{date}/{report_name}")
print(f"'{report_name}' generated successfully.\n")