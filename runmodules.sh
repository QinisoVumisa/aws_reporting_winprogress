#!/bin/bash


printf "Scan performed using the following variables:\n"
printf "Customer Name: $custname\n"
printf "Customer Region: $AWS_DEFAULT_REGION\n"
printf "Today's Date: $today\n"
printf "AWS Access Key ID: $AWS_ACCESS_KEY_ID\n"
printf "Boto3/CLI API Retry Mode: $AWS_RETRY_MODE\n"
printf "Maximum number of retries: $AWS_MAX_ATTEMPTS\n"


## Get Account Context
#printf " -------------------------------------------------------------------------\nFetching account context:"
printf "Getting account id:  "
calleridentity=`aws sts get-caller-identity --output json 2> /dev/null` ## Get account id.
if [[ ${#calleridentity} -gt 2 ]] ## Make sure we got a return value
    then accountid=`jq -r '.Account' <<< $calleridentity 2> /dev/null`
fi
printf "$accountid \xe2\x9c\x85 \n"
export accountid=$accountid

if [[ -z "$accountid" ]]
then 
echo "Problem with credentials"
exit 0
fi


#printf "# -------------------------------------------------------------------------\nFetching account context is complete\n# -------------------------------------------------------------------------\n"

printf "\n"

 ##./modules/get-accountid.sh
./modules/generate-sample-finding.sh
./modules/monitoring.sh
./modules/guardduty-main.sh
#/modules/guardduty-low.sh
#./modules/compliance-scores.sh
## ./modules/compliance-matrix.sh
#./modules/compliance-matrix.sh
#./modules/compliance-critical-high-controls.sh
#./modules/compliance-urgent.sh
#./modules/compliance-ec2.sh
##./modules/detail-account-names.sh
#./modules/compliance-top5failingresources.sh
#./modules/compliance-suppressed.sh
./modules/resolve-sample-finding.sh

