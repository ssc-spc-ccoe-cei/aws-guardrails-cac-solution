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
SAM_TRANSFORM_IDENFITIER="Transform: AWS::Serverless"
if [[ $BUILD_DIR == "" ]]; then
  BUILD_DIR='build'
fi
if [[ $SEARCH_PATH == "" ]]; then
  SEARCH_PATH='./'
fi
for file in $(find $SEARCH_PATH -name template.yaml | xargs realpath); do
  path=$(dirname $file)
  if [[ $path == */build ]]
  then
    echo "$path is a build directory. SKIPPING... ❎"
  else
    echo $path
    cd $path
    IS_SAM_TEMPLATE=`grep "$SAM_TRANSFORM_IDENFITIER" $file | wc -l`
    if [[ $IS_SAM_TEMPLATE -eq 1 ]]; then
      sam build -b ./$BUILD_DIR/ -u
      if [[ $? -ne 0 ]]; then
        echo "Failed to Build SAM for $path ❌"
        exit 1
      fi
      ## Below needed as sam does not copy *.so libs into builds https://github.com/aws/aws-sam-cli/issues/1360
      LIBRARY_FILES=(./src/lib/*.so)
      if [[ -f $LIBRARY_FILES ]]; then
        cp ./src/lib/*.so ./$BUILD_DIR/*/lib
      fi
    else
      echo "Not a SAM TEMPLATE ❌"
    fi
  fi
done

echo ""
echo "SAM Build Complete! ✅"