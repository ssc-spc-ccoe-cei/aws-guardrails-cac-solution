#!/bin/bash
declare -a arr=("gc-awsconfigconforms-oh4a3zc5ux" "gc-evidence-oh4a3zc5ux")

for (( i = 0; i < ${#arr[@]} ; i++ )); do
    printf "\n**** Deleting bucket: ${arr[$i]} 🚀🚀🚀 *****\n\n"
    aws s3 rm s3://${arr[$i]} --recursive
    aws s3 rb s3://${arr[$i]} --force
done
