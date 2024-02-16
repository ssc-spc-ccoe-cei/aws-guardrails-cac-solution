# Enhancing the Existing Solution

## Enhancement Steps

### 1.0 Create a new StackSet

- Create a new StackSet template mapping the new rules (custom lambda functions) based on the existing templates
- Add the new StackSet to the ```main.yaml``` after the last one, e.g., after ```AuditAccountPreRequisitesPart8```

### 2.0 Update Dependencies

- Add the new lambda mappings to the ```aws_lambda_permissions_setup``` function
- Update ```GCLambdaExecutionRole``` and ```GCLambdaExecutionRole2``` mappings based on required IAM in ```AllAccountPreRequisites.yaml```
- Update ```GCLambdaExecutionRole```and ```GCLambdaExecutionRole2``` mappings based on required IAM in ```main.yaml```

### 3.0 Update Conformance Pack

- Add the new rules to the ```ConformancePack.yaml``` definition

### 4.0 Redeploy the main stack

- Redeploy the main stack via makefile or manually

## Notes

- Ensure to follow the same prefixes and naming convention as per current
  - Setup lambdas should start with AWS_
  - Guardrails lambdas should start with GC_
