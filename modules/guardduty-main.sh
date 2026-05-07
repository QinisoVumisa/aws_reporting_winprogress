#!/bin/bash


# set date variables
startoflastmonth=$(date -v1d -v-1m +%Y-%m-%d)
endoflastmonth=$(date -v1d -v-1d +%Y-%m-%d)
startof2monthsago=$(date -v1d -v-2m +%Y-%m-%d)
endof2monthsago=$(date -v1d -v-1m -v-1d +%Y-%m-%d)
startof3monthsago=$(date -v1d -v-3m +%Y-%m-%d)
endof3monthsago=$(date -v1d -v-2m -v-1d +%Y-%m-%d)

printf "\n\n"
printf "================================================================================\n"
printf "GUARDDUTY INCIDENTS SECTION\n-"
printf "\nGuardDuty detects anomalous activity in the environment\n"
printf "================================================================================\n\n"
#printf "\n"


# PULL GUARDDUTY STATS

#printf "Incident count: Current reporting month: $startoflastmonth to $endoflastmonth\n"
#printf "HIGH:\t\t"
thismonthhigh=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startoflastmonth"'","End":"'"$endoflastmonth"'"}]}'  |jq '.Findings | length')
#echo $thismonthhigh

#printf "MEDIUM:\t\t"
thismonthmedium=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startoflastmonth"'","End":"'"$endoflastmonth"'"}]}'  |jq '.Findings | length')
#echo $thismonthmedium

#printf "LOW:\t\t"
thismonthlow=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startoflastmonth"'","End":"'"$endoflastmonth"'"}]}'  |jq '.Findings | length')
#echo $thismonthlow

#printf "TOTAL:\t\t"
thismonthtotal=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startoflastmonth"'","End":"'"$endoflastmonth"'"}]}'  |jq '.Findings | length')
#echo $thismonthtotal

#printf "\nIncident count: previous reporting month: $startof2monthsago to $endof2monthsago\n"

#printf "HIGH:\t\t"

lastmonthhigh=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startof2monthsago"'","End":"'"$endof2monthsago"'"}]}'  |jq '.Findings | length')
#echo $lastmonthhigh

#printf "MEDIUM:\t\t"
lastmonthmedium=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startof2monthsago"'","End":"'"$endof2monthsago"'"}]}'  |jq '.Findings | length')
#echo $lastmonthmedium

#printf "LOW:\t\t"
lastmonthlow=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startof2monthsago"'","End":"'"$endof2monthsago"'"}]}'  |jq '.Findings | length')
#echo $lastmonthlow

#printf "TOTAL:\t\t"
lastmonthtotal=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startof2monthsago"'","End":"'"$endof2monthsago"'"}]}'  |jq '.Findings | length')
#echo $lastmonthtotal

#printf "\nIncident count: Two reporting months ago: $startof3monthsago to $endof3monthsago\n"

#printf "HIGH:\t\t"
threemonthhigh=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startof3monthsago"'","End":"'"$endof3monthsago"'"}]}'  |jq '.Findings | length')
#echo $threemonthhigh

#printf "MEDIUM:\t\t"
threemonthmedium=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startof3monthsago"'","End":"'"$endof3monthsago"'"}]}'  |jq '.Findings | length')
#echo $threemonthmedium

#printf "LOW:\t\t"
threemonthlow=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startof3monthsago"'","End":"'"$endof3monthsago"'"}]}'  |jq '.Findings | length')
#echo $threemonthlow

#printf "TOTAL:\t\t"
threemonthtotal=$(aws securityhub get-findings   --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startof3monthsago"'","End":"'"$endof3monthsago"'"}]}'  |jq '.Findings | length')
#echo $threemonthtotal

monthname3monthsago=$(date -j -f "%Y-%m-%d" "$endof3monthsago" '+%b' 2>/dev/null || date -v-3m '+%b')
monthname2monthsago=$(date -j -f "%Y-%m-%d" "$endof2monthsago" '+%b' 2>/dev/null || date -v-2m '+%b')
monthname1monthsago=$(date -j -f "%Y-%m-%d" "$endoflastmonth" '+%b' 2>/dev/null || date -v-1m '+%b')



printf "Incident 3-month trend: \t $monthname3monthsago \t $monthname2monthsago \t $monthname1monthsago \n\n"
printf "HIGH:\t\t\t\t  $threemonthhigh \t  $lastmonthhigh \t  $thismonthhigh\n"
printf "MEDIUM:\t\t\t\t  $threemonthmedium \t  $lastmonthmedium \t  $thismonthmedium\n"
printf "LOW:\t\t\t\t  $threemonthlow \t  $lastmonthlow \t  $thismonthlow\n"
printf "TOTAL:\t\t\t\t  $threemonthtotal \t  $lastmonthtotal \t  $thismonthtotal\n"






printf "\n\n"
printf "==========\nINCIDENT DETAIL for the current reporting month: $startoflastmonth to $endoflastmonth\n==========\n\n"


#printf "===\n"
printf "HIGH\n"
printf "====\n"

aws securityhub get-findings --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startoflastmonth"'","End":"'"$endoflastmonth"'"}]}' | jq -r '(.Findings|=sort_by(.AwsAccountId)|.Findings[]|[.AwsAccountId,.Resources[].Details.AwsIamAccessKey.PrincipalId // "-",  .Resources[].Details.AwsIamAccessKey.PrincipalName // "-",.Types[], .Title, .Id])'

# aws securityhub get-findings --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "HIGH","Comparison": "EQUALS"}],"CreatedAt": [{"Start": "'$(date -d '-30 days' +'%Y-%m-%dT%H:%M:%SZ')'","End": "'$(date +'%Y-%m-%dT%H:%M:%SZ')'"}]}' | jq -r '(.Findings|=sort_by(.AwsAccountId)|.Findings[]|[.AwsAccountId,.Resources[].Details.AwsIamAccessKey.PrincipalId // "-",  .Resources[].Details.AwsIamAccessKey.PrincipalName // "-",.Types[], .Title, .Id])'

printf "\n"
#printf "====\n"
printf "MEDIUM\n"
printf "======\n"

aws securityhub get-findings --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startoflastmonth"'","End":"'"$endoflastmonth"'"}]}' | jq -r '(.Findings|=sort_by(.AwsAccountId)|.Findings[]|[.AwsAccountId,.Resources[].Details.AwsIamAccessKey.PrincipalId // "-",  .Resources[].Details.AwsIamAccessKey.PrincipalName // "-",.Types[], .Title, .Id])'

# aws securityhub get-findings --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "MEDIUM","Comparison": "EQUALS"}],"CreatedAt": [{"Start": "'$(date -d '-30 days' +'%Y-%m-%dT%H:%M:%SZ')'","End": "'$(date +'%Y-%m-%dT%H:%M:%SZ')'"}]}' | jq -r '(.Findings|=sort_by(.AwsAccountId)|.Findings[]|[.AwsAccountId,.Resources[].Details.AwsIamAccessKey.PrincipalId // "-",  .Resources[].Details.AwsIamAccessKey.PrincipalName // "-",.Types[], .Title, .Id])'

printf "\n"
#printf "===\n"
printf "LOW\n"
printf "===\n"

aws securityhub get-findings --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"CreatedAt": [{"Start":"'"$startoflastmonth"'","End":"'"$endoflastmonth"'"}]}' | jq -r '(.Findings|=sort_by(.AwsAccountId)|.Findings[]|[.AwsAccountId,.Resources[].Details.AwsIamAccessKey.PrincipalId // "-",  .Resources[].Details.AwsIamAccessKey.PrincipalName // "-",.Types[], .Title, .Id])'

# aws securityhub get-findings --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"ProductFields": [{"Key": "aws/securityhub/ProductName","Value": "GuardDuty","Comparison": "EQUALS"}],"SeverityLabel": [{"Value": "LOW","Comparison": "EQUALS"}],"CreatedAt": [{"Start": "'$(date -d '-30 days' +'%Y-%m-%dT%H:%M:%SZ')'","End": "'$(date +'%Y-%m-%dT%H:%M:%SZ')'"}]}' | jq -r '(.Findings|=sort_by(.AwsAccountId)|.Findings[]|[.AwsAccountId,.Resources[].Details.AwsIamAccessKey.PrincipalId // "-",  .Resources[].Details.AwsIamAccessKey.PrincipalName // "-",.Types[], .Title, .Id])'