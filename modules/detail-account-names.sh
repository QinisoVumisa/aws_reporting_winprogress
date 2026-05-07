
# need to get access to root account and write output to a file

#printf "\n======\nList of AWS account detail provided by AWS Organisations (Landing Zone)\n======"
#aws organizations list-accounts |jq '(.Accounts[]|[.Id, .Name, .Email])' -c | sort |sed 's/^.//' | sed 's/.$//'

