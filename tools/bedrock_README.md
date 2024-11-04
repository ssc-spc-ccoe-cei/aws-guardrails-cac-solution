*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# ./bedrock_readme.py

This utility uses AWS Bedrock to generate README.md files from application code.

## Usage

It accepts the following arguments:

- `--model`: Model ID, you must be subscribed to this in the reference aws account (required)
- `--input`: Application code to process (required)  
- `--output`: Output file name (required)
- `--path`: Path to search and generate README.md (optional)

If `--path` is provided, it will search all subdirectories and generate a README.md next to any code files matching `--input`.

If `--path` is not provided, it will generate a README.md in the current working directory.

## Code Overview

- Imports boto3, json, argparse, and os modules
- Creates a Bedrock client
- Defines prompt strings
- Parses command line arguments 
- Gets list of subdirectories if `--path` provided
- Loops through subdirectories:
  - Checks if code file exists
  - Reads code file
  - Creates Bedrock request with code and prompt
  - Calls Bedrock `invoke_model` API
  - Gets response and extracts markdown output
  - Writes output to README.md

The main logic generates a prompt with the code, calls the Bedrock API to get the model's markdown documentation, and writes it to the README.md.
