#!/bin/bash

today=$(date +"%Y-%m-%d")

tar -czvf $today-backup-v3.tgz ./*.sh ./modules/*
aws --profile instance-profile s3 cp ./$today-backup-v3.tgz s3://synthesis-mcs-reports/aws-reporting/v3/
rm $today-backup-v3.tgz
