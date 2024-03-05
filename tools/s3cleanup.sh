#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <AccountID> <Role> <BucketNamePrefix1> [BucketNamePrefix2] ..."
    exit 1
fi

AccountID=$1
Role=$2

# Removing first two arguments to loop through the remaining ones
shift 2

# Assume role and export credentials
RoleSessionName="S3BucketManagementSession"

AssumeRoleOutput=$(aws sts assume-role --role-arn arn:aws:iam::${AccountID}:role/${Role} --role-session-name ${RoleSessionName})

if [ $? -ne 0 ]; then
    echo "Failed to assume role ${Role} in account ${AccountID}."
    exit 1
fi

export AWS_ACCESS_KEY_ID=$(echo ${AssumeRoleOutput} | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo ${AssumeRoleOutput} | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo ${AssumeRoleOutput} | jq -r '.Credentials.SessionToken')

# Loop through the bucket name prefixes
for prefix in "$@"; do
    # List buckets with the given prefix
    buckets=$(aws s3api list-buckets --query "Buckets[?starts_with(Name, \`${prefix}\`)].Name" --output text)

    for bucket in $buckets; do
        echo "Emptying bucket: $bucket"

        # Empty the bucket
        aws s3 rm s3://$bucket --recursive

        if [ $? -ne 0 ]; then
            echo "Failed to empty bucket ${bucket}."
            continue
        fi
        
        #Note: Deleting the bucket is not recommended as it may cause issues when deleting stack, use it only when needed
        # echo "Deleting bucket: $bucket"

        # # Delete the bucket
        # aws s3api delete-bucket --bucket $bucket

        # if [ $? -ne 0 ]; then
        #     echo "Failed to delete bucket ${bucket}."
        # else
        #     echo "Bucket $bucket deleted successfully."
        # fi
    done
done

# Unset the temporary credentials
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

echo "Operation completed."
