#!/usr/bin/env python3
# © 2023 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.  
# This AWS Content is provided subject to the terms of the AWS Customer Agreement available at  
# http://aws.amazon.com/agreement or other written agreement between Customer and either
# Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.
import boto3
import ruamel.yaml as yaml
import json
from botocore.exceptions import ClientError
import argparse
import warnings
warnings.simplefilter('ignore', yaml.error.UnsafeLoaderWarning)

global config
s = boto3.Session()

def get_cfn_outputs(stack_name, session):
  # Gets the outputs of a CloudFormation stack
  cfn_client = session.client('cloudformation')
  response = cfn_client.describe_stacks(StackName=stack_name)
  outputs = response['Stacks'][0]['Outputs']
  return outputs

def value_in_list(value, list):
  # Checks if a value is in a list
  for item in list:
    if value == item['ParameterKey']:
      return True
  return False

def update_json(json_file, output_list):
  # Updates a json file with the output of a CloudFormation stack
  with open(json_file, 'r') as f:
    config = json.load(f)
  for item in output_list:
    if value_in_list(item['OutputKey'], config['Parameters']):
      print(f"Parameter {item['OutputKey']} already exists")
      config['Parameters'] = [obj for obj in config['Parameters']
                              if obj['ParameterKey'] != item['OutputKey']]
    config['Parameters'].append({
        "ParameterKey": f"{item['OutputKey']}",
        "ParameterValue": f"{item['OutputValue']}"
      })
  with open(json_file, 'w') as f:
    json.dump(config, f, indent=4)

parser=argparse.ArgumentParser(
  description = 'Utility to update config files from the output of a CloudFormation stack')
parser.add_argument('--stack', help = 'CloudFormation stack name',
  nargs = '?', required = True)
parser.add_argument('--update', help = 'json file to update',
  nargs = '?', required = True)
args=parser.parse_args()

output = get_cfn_outputs(stack_name=args.stack, session=s)
update_json(json_file=args.update, output_list=output)