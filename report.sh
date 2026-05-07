#!/bin/bash

# Prerequisites:  JQ installed 

#changelog 30 Dec 
# This version has brand new DynamoDB function. Maybe some more error correction/detection required.
# both S3 upload and email sending are commented out for testing




today=$(date +"%Y-%m-%d")


if [[ -z "$AWS_ACCESS_KEY_ID" ]]; then source ./dynamodb.sh; fi


if [[ -z "$AWS_ACCESS_KEY_ID" ]]; then echo "Credentials Not Found. Please paste SSO creds into terminal and re-run application"; exit 0; fi



if [[ -z "$custname" ]]; then
echo Enter customer name:
read custname
if [[ -z "$custname" ]]; then printf "Exiting. Customer name is required.\n" && exit 1; fi	
fi


if [[ -z "$custregion" ]]; then
echo Enter security hub aggregate region:[eu-west-1]:
read custregion
custregion=${custregion:="eu-west-1"}
fi


#export custregion=eu-west-1
export AWS_DEFAULT_REGION=$custregion
export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS=10
export custname=$custname
export today=$today

thismonth=$(date +%Y-%m)

mkdir -p ./OUTPUT/$thismonth/
 ./runmonitoring.sh | tee ./OUTPUT/$thismonth/$today.$custname.infosec-monitoring-report-tabbed.txt
expand ./OUTPUT/$thismonth/$today.$custname.infosec-monitoring-report-tabbed.txt > ./OUTPUT/$thismonth/$today.$custname.infosec-monitoring-report.txt
rm ./OUTPUT/$thismonth/$today.$custname.infosec-monitoring-report-tabbed.txt 


 ./runcompliance.sh | tee ./OUTPUT/$thismonth/$today.$custname.infosec-compliance-report-tabbed.txt
expand ./OUTPUT/$thismonth/$today.$custname.infosec-compliance-report-tabbed.txt > ./OUTPUT/$thismonth/$today.$custname.infosec-compliance-report.txt
rm ./OUTPUT/$thismonth/$today.$custname.infosec-compliance-report-tabbed.txt


python3 report.py $custname


unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN


# UNCOMMENT the following after promoting to PROD
# aws --region eu-west-1 --profile instance-profile s3 cp ./OUTPUT/$thismonth/$today.$custname.infosec-monitoring-report.txt s3://synthesis-mcs-reports/reports/$thismonth/
# aws --region eu-west-1 --profile instance-profile s3 cp ./OUTPUT/$thismonth/$today.$custname.infosec-compliance-report.txt s3://synthesis-mcs-reports/reports/$thismonth/
# aws --region eu-west-1 --profile instance-profile s3 cp "./OUTPUT/$thismonth/${thismonth} - ${custname} - Monthly Security Essentials Report.docx" s3://synthesis-mcs-reports/reports/$thismonth/

sleep 1

echo "Automatically generated security and compliance report for: " $custname | mutt -s "Security and Compliance report for: $custname for $thismonth" -a "./OUTPUT/$thismonth/$today.$custname.infosec-monitoring-report.txt" -a "./OUTPUT/$thismonth/$today.$custname.infosec-compliance-report.txt" -a "./OUTPUT/$thismonth/${thismonth} - ${custname} - Monthly Security Essentials Report.docx" -e 'my_hdr From:noreply@synthesis-mcs.com' -- mcs@synthesis.co.za

unset custname
unset custregion
unset accountid
unset today
unset thismonth

printf "Done \xe2\x9c\x85 \n"


