#!/usr/bin/env python3
# © 2023 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
# This AWS Content is provided subject to the terms of the AWS Customer Agreement available at
# http://aws.amazon.com/agreement or other written agreement between Customer and either
# Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.
import boto3
import json
import argparse
import os

bedrock_client = boto3.client("bedrock-runtime")
HUMAN_PROMPT = "\n\nHuman:"
AI_PROMPT = "\n\nAssistant:"


parser = argparse.ArgumentParser(
    description='AWS Bedrock utility to generate README.md files from application code')
parser.add_argument('--model', help='Model ID, you must be subscribed to this in the reference aws account',
                    nargs='?', required=True)
parser.add_argument('--input', help='application code to process',
                    nargs='?', required=True)
parser.add_argument('--output', help='Output file',
                    nargs='?', required=True)
parser.add_argument('--path', help='Path to search and generate README.md',
                    nargs='?', required=False)
args = parser.parse_args()
sub_dirs = []
if args.path:
    for root, dirs, files in os.walk(args.path):
      sub_dirs.append(root)
else:
    sub_dirs = [os.getcwd()]

for sub_dir in sub_dirs:
    if os.path.isfile(f"{sub_dir}/{args.input}"):
      print(f"Reading: {sub_dir}/{args.input}")

      with open(f"{sub_dir}/{args.input}", "r", encoding="utf-8") as config_file:
          app_code = config_file.read()

      request = {
          "prompt": f"""{HUMAN_PROMPT}
      Generate a README.md using markdown based on the code inside <app_code></app_code> XML tags.
      If you do not understand what a function does or you cannot make a well-informed guess say you don't know.
      Use {sub_dir}/{args.input} as the name.
      If a lambda_handler function exists, it is always the main entry point.
      Do not add documentation for Testing.
      Do not add documentation for Logging.
      <app_code>
      {app_code}
      </app_code>

      {AI_PROMPT}""",
              "max_tokens_to_sample": 3500,
              "temperature": 1,
          }

      response = bedrock_client.invoke_model(
          modelId=args.model,
          body=json.dumps(request),
      )

      response_body = json.loads(
          response["body"].read().decode("utf-8"))["completion"]
      output = response_body.strip().split("\n", 1)[1]
      output = f"*This readme file was created by AWS Bedrock: {args.model}*\n{output}"

      print(f"Writing: {sub_dir}/{args.output}")

      with open(f"{sub_dir}/{args.output}", 'w', encoding="utf-8") as f:
          print(output, file=f)
