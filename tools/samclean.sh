#!/bin/bash
while getopts ":p:h" opt; do
  case ${opt} in
    p )
      SEARCH_PATH=$OPTARG
      ;;
    b )
      BUILD_DIR=$OPTARG
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

if [[ $BUILD_DIR == "" ]]; then
  BUILD_DIR='build'
fi

for file in $(find $SEARCH_PATH -name build.toml | xargs realpath); do
  path=$(dirname $file)
  cd $path --no-messages
  rm -fr $path/build --no-messages
  rm -rf $path/.aws-sam --no-messages
done

echo ""
echo "SAM Cleanup Complete! ✅"