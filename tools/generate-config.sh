#!/bin/bash
while getopts ":e" opt; do
  case ${opt} in
    b )
      ENVIRONMENT_NAME=$OPTARG
      ;;
    \? )
      echo "Invalid option: $OPTARG" 1>&2
      ;;
    : )
      echo "Invalid option: $OPTARG requires an argument" 1>&2
      ;;
  esac
done
shift $((OPTIND -1))

cp ./arch/params/base.json ./arch/params/${ENVIRONMENT_NAME}.json
cp ./arch/params/base.tags ./arch/params/${ENVIRONMENT_NAME}.tags
cp ./arch/params/policy.json ./arch/params/${ENVIRONMENT_NAME}-policy.json
