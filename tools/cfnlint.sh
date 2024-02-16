#!/bin/bash
shopt -s extglob
set -e
for file in **/*.yaml; do
    if [ "\$(sed -n '/^AWSTemplateFormatVersion/p;q' "$file")" ]; then
        cfn-lint "$file" -f pretty 2
    fi
done
