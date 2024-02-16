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


def get_parameters(param_list, session):
  # Gets the values of a list of parameters from a session and returns the key value list
  param_values = []
  ssm_client = session.client('ssm')
  secret_client = session.client('secretsmanager')
  ec2_client = session.client('ec2')
  for param in param_list:
    if param['Value'] == "":
      if param['Location'] != 'resolved':
        if param['Type'] == 'ssm-param':
          print(f"Obtaining value - {param['Type']}: {param['Location']}")
          ssm_client_response = ssm_client.get_parameter(
              Name=param['Location'])
          param_values.append({
              'Name': param['Name'], 'Location': param['Location'], 'Value': ssm_client_response['Parameter']['Value']
          })
          if param['Name'] == 'VpcId':
            vpc_id = ssm_client_response['Parameter']['Value']
        if param['Type'] == 'secret':
          secret_client_response = secret_client.get_secret_value(
              SecretId=param['Location'])
          param_values.append({
              'Name': param['Name'], 'Location': param['Location'], 'Value': secret_client_response['SecretString']
          })
        if param['Type'] == 'vpc-endpoint':
          print(f"Obtaining VPC endpoint: {param['Location']}")
          ec2_client_response = ec2_client.describe_vpc_endpoints(
              Filters=[
                  {
                      'Name': 'service-name',
                      'Values': [param['Location']]
                  }
              ]
          )
          if "VpcEndpointId" in str(ec2_client_response):
            param_values.append({
                'Name': param['Name'], 'Location': param['Location'], 'Value': ec2_client_response['VpcEndpoints'][0]['VpcEndpointId']
            })
          else:
            param_values.append({
                'Name': param['Name'], 'Location': param['Location'], 'Value': ''
            })
      else:
        if param['Name'] == 'VpcCidr':
          vpc_cidr = get_cidr(vpc_id=vpc_id, session=session)
          param_values.append({
              'Name': param['Name'], 'Location': param['Location'], 'Value': vpc_cidr
          })
    else:
      param_values.append({
          'Name': param['Name'], 'Location': param['Location'], 'Value': param['Value']
      })
  return(param_values)


def get_cidr(vpc_id, session):
  ec2_client = session.client('ec2')
  ec2_client_response = ec2_client.describe_vpcs(
      VpcIds=[vpc_id]
  )
  for vpc in ec2_client_response['Vpcs']:
    cidr_block = vpc['CidrBlock']
  return(cidr_block)


parser = argparse.ArgumentParser(
    description='Utility to generate conf.json files from a yaml config file and AWS param/secrets values')
parser.add_argument('--input', help='config to parse',
                    nargs='?', required=True)
parser.add_argument('--output', help='json file to output',
                    nargs='?', required=True)
args = parser.parse_args()


with open(args.input, "r") as config_file:
    config = yaml.load(config_file.read().replace(
        '\t', '  '), yaml.RoundTripLoader)
    print(f"using configuration in {args.input}")

assumed_role = boto3.Session()
json_list = []
try:
  print("Obtaining AWS parameters")
  values = get_parameters(
      param_list=config['CloudFormation']['ParameterStore'],
      session=assumed_role
  )

  config['CloudFormation']['ParameterStore'] = values

  for item in values:
    json_list.append(
        {
            "ParameterKey": f"{item['Name']}",
            "ParameterValue": f"{item['Value']}"
        }
    )
except:
  print("No computed parameters found")
  
for key, value in list(config['Parameters'].items()):
  json_list.append({
      "ParameterKey": f"{key}",
      "ParameterValue": f"{value}"
  })
parameters = {"Parameters": json_list}

j = json.dumps(parameters, indent=4)

print(f"Dumping parameters to {args.output}")

with open(args.output, 'w') as f:
    print(j, file=f)

with open('out.yaml', 'w') as ofp:
    yaml.dump(config, ofp, default_flow_style=False,
              Dumper=yaml.RoundTripDumper)
