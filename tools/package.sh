#!/bin/bash
REGION='ca-central-1'
while getopts ":b:r:t:g:p:h" opt; do
  case ${opt} in
    b )
      BUCKET=$OPTARG
      ;;
    r )
      REGION=$OPTARG
      ;;
    t )
      TEMPLATE_DIR=$OPTARG
      ;;
    g )
      GIT_SOURCE_VERSION=$OPTARG
      ;;
    p )
      TEMPLATEPACKAGED_DIR=$OPTARG
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

RELATIVE_SCRIPT_DIR=$(dirname $0)
RELATIVE_SCRIPT_DIR=${RELATIVE_SCRIPT_DIR#./}
FULL_SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

if [[ $BUCKET == "" ]]; then
  echo "Must Supply Bucket to package into"
  exit 1
fi

if [[ $GIT_SOURCE_VERSION == "" ]]; then
  echo "Must Supply git source version"
  exit 1
fi

if [[ $REGION == "" ]]; then
  REGION=$AWS_REGION
fi

if [[ $TEMPLATE_DIR == "" ]]; then
  TEMPLATE_DIR="${FULL_SCRIPT_DIR%/$RELATIVE_SCRIPT_DIR}/arch/templates"
fi
if [[ $TEMPLATEPACKAGED_DIR == "" ]]; then
  TEMPLATEPACKAGED_DIR="${FULL_SCRIPT_DIR%/$RELATIVE_SCRIPT_DIR}/arch/templates/build"
fi
mkdir -p $TEMPLATEPACKAGED_DIR
echo "$REGION"
## any child templates that is not the main template
for fp in "$TEMPLATE_DIR"/*.yaml; do
  file=$(basename $fp)
  if [ $file != 'main.yaml' ]; then
    aws cloudformation package --s3-bucket $BUCKET --force-upload --template-file "$fp" --output-template-file "$TEMPLATEPACKAGED_DIR/$file" --region $REGION || { echo "Error while packaging file $file."; exit 1; }
    aws s3 cp "$TEMPLATEPACKAGED_DIR/$file" "s3://$BUCKET/$file" --region $REGION
  fi
done

## main template packaging
aws cloudformation package --s3-bucket $BUCKET --force-upload --template-file "$TEMPLATE_DIR/main.yaml" --output-template-file "$TEMPLATEPACKAGED_DIR/main.yaml" --region $REGION  || { echo "Error while packaging file main.yaml."; exit 1; }

## Store the pipeline git hash as an artifact.
JSON_FMT='{"CodeBuildResolvedSourceVersion":"%s"}\n'
printf "$JSON_FMT" "$GIT_SOURCE_VERSION" > "$TEMPLATEPACKAGED_DIR/git.json"

echo ""
echo "Packaging Complete! ✅"
