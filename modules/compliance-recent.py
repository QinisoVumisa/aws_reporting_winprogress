# ### Created by: Qiniso Vumisa ###

# ##################################################################################
# # Libraries that are required for the customer report to be generated.
# ##################################################################################
# import docx 
# import matplotlib
# import pandas as pd
# from docx import Document
# from datetime import datetime
# from docx.shared import Pt
# from docx.enum.text import WD_PARAGRAPH_ALIGNMENT

# ##################################################################################
# # Modules that are required for the customer report to be generated.
# ##################################################################################

# import variables # variables.py
# import formatting # formatting.py
# import process_json # process_json.py

# ##################################################################################
# # Variables that are required for the customer report to be generated.
# ##################################################################################

# # The customer name to be used throughout the report
# customer_name = variables.customer_name

# ##################################################################################

# ##################################################################################
# # This is the main file which will generate the document.
# ##################################################################################

# # The date formats to be used throughout the report
# full_date = datetime.now().strftime('%B %Y') # Month Year - For Title Page
# date = datetime.now().strftime('%Y-%m') # YYYY-MM - For File Name

# # The name of the report when it is done
# report_name = f'{date} - {customer_name} - Network Vulnerability Report.docx'

# print(f"Generating '{report_name}'.\n")

# # Open the template
# doc = Document('YYYY-MM - Customer Name - Network Vulnerability Report.docx')

# # Define font settings
# font_name = 'Calibri'
# font_size = Pt(12)

# # Line spacing
# line = "\n"

# # Set default font for the entire document
# doc.styles['Normal'].font.name = font_name
# doc.styles['Normal'].font.size = font_size

# # Add the title to the Title Property
# title_property = doc.core_properties.title
# doc.core_properties.title = customer_name
# title_property = doc.core_properties.subject
# doc.core_properties.subject = "Network Vulnerability Report"

# # Add the date to the Publish Date property
# date_property = doc.core_properties.comments
# doc.core_properties.comments = full_date

# # Add a paragraph for the Table of Contents
# toc_paragraph = doc.add_paragraph()
# toc_run = toc_paragraph.add_run()
# toc_run.text = 'Table of Contents'
# toc_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

# # Add the field code for the TOC directly to the run's text
# toc_run.text += ' TOC \\o "1-3" \\h \\z '

# # Apply formatting to the TOC
# toc_run.font.size = Pt(12)
# toc_run.bold = True

# # Add a page break
# doc.add_page_break()

# # Overview
# doc.add_heading('Summary of deployment and configuration', level=1)

# # Add introductory text
# deployment_text = f"A server hosted in the {customer_name} AWS “shared” environment performs a weekly network scan of all IP subnets within AWS (Across all LZ accounts){line}A cloud server hosted at Tenable (Frankfurt) will perform a weekly vulnerability scan against a list of public endpoints/domains. List to be provided by Riskscape.{line}Scans are currently scheduled to run once per week on Saturday at 8pm{line}To save cost, the scanning EC2 is scheduled to automatically shut down for the rest of the week.{line}This is the initial report, some formatting modifications will take place over the coming months as we improve our reporting automation and asset identification capability.{line}Further LZ-wide configuration may be required to “open up” all EC2 security groups to the internal scanner CIDR range for more visibility."
# doc.add_paragraph(deployment_text)
# # deployment_paragraph.style = 'List Bullet'

# # Add line space
# doc.add_paragraph(line)

# # Purpose
# doc.add_heading('External (Public Domain) Network Scan Results', level=1)

# # Add introductory text
# domain_text = f"Note: An external scan has not yet been performed. This will be configured once confirmation on which hostname should be scanned, and will be included in future reports."
# doc.add_paragraph(domain_text)

# # Add a page break
# doc.add_page_break()

# # Scope
# doc.add_heading('Internal (AWS LZ) Network Scan Results', level=1)

# # Vulnerability Matrix
# doc.add_heading('Findings By Host', level=2)#.bold = True

# # Add introductory text
# scan_text = f"This section gives a summary of the vulnerabilities found for each host."
# doc.add_paragraph(scan_text)

# # Add a line space
# doc.add_paragraph(line)

# # Create the table with headings
# table = doc.add_table(rows=1, cols=3)
# table.style = 'Table Grid'

# # Set the column headers
# headers = ['Host name', 'Findings', 'Total findings']
# for col_num, header_text in enumerate(headers):
#     cell = table.cell(0, col_num)
#     cell.text = header_text
#     cell.paragraphs[0].runs[0].bold = True
    
#     # Apply shading to the header row
#     shading_color = '808080'
#     formatting.apply_cell_shading(cell, shading_color)

# # Add data rows
# count = 0
# while count <= len(process_json.vuln_matrix):
#     if process_json.pid_list[count] in process_json.id_list:
#         id = process_json.pid_list[count]
#         row_cells = table.add_row().cells
#         row_cells[0].text = str(process_json.vuln_matrix[id]['host'])
#         # Add bar chart to the cell in the second column 
#         bar_chart_data = process_json.host_matrix[process_json.vuln_matrix[id]['host']]['findings']
#         categories = []
#         values = []

#         for data in bar_chart_data:
#             words = data.split(':')
#             category = words[0].strip()
#             value = int(words[1].strip())
#             categories.append(category)
#             values.append(value)

#         # bar_chart = formatting.create_bar_chart(categories, values, xlabel='Categories', ylabel='Values', title='Bar Chart')
#         # formatting.insert_chart_into_cell(row_cells[1], bar_chart)
#         row_cells[1].text = str(process_json.host_matrix[process_json.vuln_matrix[id]['host']]['findings'])
#         row_cells[2].text = str(process_json.host_matrix[process_json.vuln_matrix[id]['host']]['total'])

        
#     count += 1

# # Add a page break
# doc.add_page_break()

# # Vulnerability Matrix
# doc.add_heading('Finding Details - Ordered by severity', level=2)#.bold = True

# # Add introductory text
# detail_text = "This section details the vulnerabilities, their respective severity, and the number of hosts that are vulnerable to it."
# doc.add_paragraph(detail_text)

# # Add line space
# doc.add_paragraph(line)

# # Create the table with headings
# table = doc.add_table(rows=1, cols=3)
# table.style = 'Table Grid'

# # Set the column headers
# headers = ['Severity', 'Finding', 'Affected hosts']
# for col_num, header_text in enumerate(headers):
#     cell = table.cell(0, col_num)
#     cell.text = header_text
#     cell.paragraphs[0].runs[0].bold = True
    
#     # Apply shading to the header row
#     shading_color = '808080'
#     formatting.apply_cell_shading(cell, shading_color)

# # Add data rows
# count = 0
# while count <= len(process_json.vuln_matrix):
#     if process_json.pid_list[count] in process_json.id_list:
#         id = process_json.pid_list[count]
#         row_cells = table.add_row().cells
#         row_cells[0].text = str(process_json.vuln_matrix[id]['severity'])
#         row_cells[1].text = str(process_json.vuln_matrix[id]['finding'])
#         row_cells[2].text = str(process_json.list_matrix[id]['count'])
#     count += 1

# # Add a page break
# doc.add_page_break()

# # Key Findings
# doc.add_heading('Vulnerability Age - Outstanding Remediations (Time Since Patch Publication)', level=1)

# # Add introductory text
# age_text = "This section details the age of the vulnerabilities, their respective severity."
# doc.add_paragraph(age_text)

# # Add line space
# doc.add_paragraph(line)

# # Summary
# doc.add_heading('Recommendations', level=1)

# # Add line space
# doc.add_paragraph(line)

# # Add a page break
# doc.add_page_break()

# # Technical Report
# doc.add_heading('Detail on the Risk of the High vulnerabilities', level=2)

# detail_text = f"The exploits either require the servers to be behind a reverse proxy in order to abuse the “request smuggling” exploits. The other vulnerability could result in a denial of service. Since the Geoservers are not behind a proxy, this is not an immediate threat. It's unlikely that either of these could have been used for data loss/exfiltration in the {customer_name} environment."
# doc.add_paragraph(detail_text)

# # Add a line space
# doc.add_paragraph(line)

# for vuln in process_json.vuln_matrix:
#     if process_json.vuln_matrix[vuln]['severity'] == "critical" or process_json.vuln_matrix[vuln]['severity'] == "high":
#         doc.add_heading(f"{process_json.vuln_matrix[vuln]['finding']} - {(str(process_json.vuln_matrix[vuln]['severity'])).upper()}", level=3)
#         description_text = f"- {process_json.vuln_matrix[vuln]['description']}"
#         doc.add_paragraph(description_text)
#         # Add a line space
#         doc.add_paragraph(line)

# # Add a page break
# doc.add_page_break()

# # Summary
# doc.add_heading('Global Threat Intelligence Summary - High Level', level=1)

# # Add line space
# doc.add_paragraph(line)

# # Save the document
# doc.save(report_name)

# print(f"'{report_name}' generated successfully.\n")

import subprocess
from datetime import datetime, timedelta

standards = [
    "AWS-Foundational-Security-Best-Practices",
    "CIS AWS Foundations Benchmark",
    "PCI-DSS"
]

print("\n================================================================================")
print("LIST OF CONTROLS FAILING IN THE LAST 30 DAYS - CRITICAL AND HIGH ONLY.")
print("================================================================================\n")

for standard in standards:
    if standard != "CIS AWS Foundations Benchmark":
        command = [
            "aws", "securityhub", "get-findings",
            "--filters",
            '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/' + standard + '","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"},{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}],"FirstObservedAt": [{"Start": "' + (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ') + '","End": "' + datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ') + '"}]}' 
        ]
    else:
        command = [
            "aws", "securityhub", "get-findings",
            "--filters",
            '{"Type": [{"Value": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"},{"Value": "HIGH","Comparison": "EQUALS"}],"WorkflowStatus": [{"Value":"SUPPRESSED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ARCHIVED","Comparison":"NOT_EQUALS"}],"FirstObservedAt": [{"Start": "' + (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ') + '","End": "' + datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ') + '"}]}' 
        ]
    
    result = subprocess.run(command, capture_output=True, text=True)
    findings = result.stdout.splitlines()

    print("Severity\tControl\tResource ID")
    print("-" * 40)

    # Extracting and formatting relevant data
    formatted_findings = []
    for line in findings[2:]:
        finding_data = line.split('\t')
        if len(finding_data) >= 3:  # Ensure we have enough elements
            severity = finding_data[0]
            title = finding_data[1]
            resource_id = finding_data[2]
            formatted_findings.append((severity, title, resource_id))
        else:
            print("Warning: Malformed line:", line)

    # Sorting by severity and control
    formatted_findings.sort(key=lambda x: (x[0], x[1]))

    # Removing duplicates
    unique_findings = []
    seen = set()
    for finding in formatted_findings:
        if finding not in seen:
            unique_findings.append(finding)
            seen.add(finding)

    # Printing first 15 unique findings
    for severity, title, resource_id in unique_findings[:15]:
        print(f"{severity}\t{title}\t{resource_id}")

    print("\n")