#!/bin/bash

# Script to query list of customers in DynamoDB table and allow user to select customer to pre-populate fields.


mapfile -t customerarray < <(aws --profile instance-profile dynamodb scan --table-name mcs-customers --projection-expression "CustomerName" | jq '(.Items[]|.CustomerName|.S)')


for i in "${!customerarray[@]}"; do
    printf "%s) %s\n" "$i" "${customerarray[$i]}"
done
printf 'Select a customer from the above list: '
IFS= read -r opt
if [[ $opt =~ ^[0-9]+$ ]] && (( (opt >= 0) && (opt <= "${#customerarray[@]}") )); then
#    printf 'Customer Selected\n'
    remotemonitoringrole=$(aws dynamodb scan --table-name mcs-customers --filter-expression "CustomerName = :CName" --expression-attribute-values "{\":CName\":{\"S\":"${customerarray[$opt]}"}}" | jq -r '(.Items[]|.RemoteMonitoringRoleArn|.S)')
    custregion=$(aws dynamodb scan --table-name mcs-customers --filter-expression "CustomerName = :CName" --expression-attribute-values "{\":CName\":{\"S\":"${customerarray[$opt]}"}}" | jq -r '(.Items[]|.SecHubRegion|.S)')
    custname=$(aws dynamodb scan --table-name mcs-customers --filter-expression "CustomerName = :CName" --expression-attribute-values "{\":CName\":{\"S\":"${customerarray[$opt]}"}}" | jq -r '(.Items[]|.CustomerName|.S)')
    externalid=$(aws dynamodb scan --table-name mcs-customers --filter-expression "CustomerName = :CName" --expression-attribute-values "{\":CName\":{\"S\":"${customerarray[$opt]}"}}" | jq -r '(.Items[]|.ExternalId|.S)')


if [[ -z "$remotemonitoringrole" ]]; then 
	echo "No External Role Found in database, attempting to retrieve access key instead";
    custregion=$(aws dynamodb scan --table-name mcs-customers --filter-expression "CustomerName = :CName" --expression-attribute-values "{\":CName\":{\"S\":"${customerarray[$opt]}"}}" | jq -r '(.Items[]|.SecHubRegion|.S)')
    custname=$(aws dynamodb scan --table-name mcs-customers --filter-expression "CustomerName = :CName" --expression-attribute-values "{\":CName\":{\"S\":"${customerarray[$opt]}"}}" | jq -r '(.Items[]|.CustomerName|.S)')
    custaccesskeyid=$(aws dynamodb scan --table-name mcs-customers --filter-expression "CustomerName = :CName" --expression-attribute-values "{\":CName\":{\"S\":"${customerarray[$opt]}"}}" | jq -r '(.Items[]|.AccessKeyId|.S)')
    custsecretaccesskey=$(aws dynamodb scan --table-name mcs-customers --filter-expression "CustomerName = :CName" --expression-attribute-values "{\":CName\":{\"S\":"${customerarray[$opt]}"}}" | jq -r '(.Items[]|.SecretAccessKey|.S)')

    export AWS_ACCESS_KEY_ID=$custaccesskeyid;\
    export AWS_SECRET_ACCESS_KEY=$custsecretaccesskey;\



else


echo "Customer Selected - Remote Security Hub Role Identified as :" $remotemonitoringrole
echo Assuming external role

OUT=$(aws --profile instance-profile sts assume-role --role-arn $remotemonitoringrole --role-session-name synthesis-mcs-remote-monitoring --external-id $externalid);\
export AWS_ACCESS_KEY_ID=$(echo $OUT | jq -r '.Credentials''.AccessKeyId');\
export AWS_SECRET_ACCESS_KEY=$(echo $OUT | jq -r '.Credentials''.SecretAccessKey');\
export AWS_SESSION_TOKEN=$(echo $OUT | jq -r '.Credentials''.SessionToken');
unset OUT


printf "Assumed the Following Identity: $AWS_ACCESS_KEY_ID \n"
aws sts get-caller-identity


fi

else
    printf 'Customer Selection Error. No external role or access key configured\n'
fi


unset remotesechubrole
unset custaccesskeyid
unset custsecretaccesskey


