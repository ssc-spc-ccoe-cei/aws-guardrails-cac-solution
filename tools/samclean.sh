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

# for file in $(find $SEARCH_PATH -name build.toml | xargs -r realpath); do
#   # path=$(dirname $file)
#   echo "path: $path, file: $file"
#   # cd $path --no-messages
#   # rm -fr $path/build --no-messages
#   # rm -rf $path/.aws-sam --no-messages
# done

while IFS= read -r file; do
  path=$(dirname "$file")
  echo "Processing directory: $path"
  # Delete the 'build' directory and '.aws-sam' directory in the found path
  rm -rf "${path}/build" "${path}/.aws-sam"
done < <(find "$SEARCH_PATH" -name 'build.toml')



echo ""
echo "SAM Cleanup Complete! ✅"