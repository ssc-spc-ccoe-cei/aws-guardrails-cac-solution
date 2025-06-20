# © 2023 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
# This AWS Content is provided subject to the terms of the AWS Customer Agreement available at
# http://aws.amazon.com/agreement or other written agreement between Customer and either
# Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.

.ONESHELL:
SHELL = /bin/bash

CONFIG_FILE ?= "config.yaml"
CODEBUILD_SRC_DIR := $(shell pwd)
AWS_REGION := $(shell yq ".AWS_REGION" $(CONFIG_FILE))
AWS_SSCSERVER := $(shell yq ".SSC_AWS_SERVER" $(CONFIG_FILE))
ACCELROLE := $(shell yq ".Parameters.AcceleratorRole" $(CONFIG_FILE))
ACCOUNT_ID := $(shell aws sts get-caller-identity --query Account --output text)
PIPELINE_BUCKET := gc-guardrails-deployments-$(ACCOUNT_ID)
DEPLOY_VERSION ?= $(shell yq ".CACVersion" ./$(CONFIG_FILE))
STACK := $(shell yq ".StackName" ./$(CONFIG_FILE))
ENV_NAME := $(shell yq ".EnvironmentName" ./$(CONFIG_FILE))
GIT_VERSION := $(shell yq ".GitSourceVersion" ./$(CONFIG_FILE))
AUDIT_ACCOUNT := $(shell yq ".Parameters.AuditAccountID" ./$(CONFIG_FILE))
PARAMETERS_STRING := jq -r '.Parameters[] | [ .ParameterKey, .ParameterValue ] | "\"\(.[0])\"=\"\(.[1])\""' ./build/params.json | tr "\n" " "
ORGANIZATION_NAME := $(shell yq ".Parameters.OrganizationName" ./$(CONFIG_FILE))
ORGANIZATION_ID := $(shell yq ".Parameters.OrganizationId" ./$(CONFIG_FILE))
SS_PARAMS := ParameterKey="AuditAccountID",UsePreviousValue=true ParameterKey="OrganizationName",UsePreviousValue=true ParameterKey="RolePrefix",UsePreviousValue=true
CLOUD_SHELL := $(shell echo $$(if [ "$$(whoami)" = "cloudshell-user" ]; then echo true; else echo false; fi))

-include tasks/Makefile.*

$(info Running in CloudShell: $(CLOUD_SHELL))
$(info CODEBUILD_SRC_DIR: $(CODEBUILD_SRC_DIR))
$(info Region: $(AWS_REGION))
$(info --- Checking dependencies ---)
ifeq (, $(shell which aws))
$(error "No aws cli installed, consider https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#getting-started-install-instructions")
endif
ifeq (, $(shell which sam))
$(error "No aws sam cli installed, consider https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html")
endif
ifeq (, $(shell which jq))
$(error "No jq cli installed, consider https://github.com/stedolan/jq")
endif
ifeq (, $(shell which yq))
$(error "No yq cli installed, consider https://github.com/mikefarah/yq")
endif
$(info --- Checking dependencies [DONE] ---)

## Make all, build and deploy
all: configure mb build-code package-code setup-organizations deploy-stack backup-config
## Build a cloudshell package, build code and package for cloudshell
build-cloudshell-package: build-code create-cloudshell-package
## Build and package code
build: build-code package-code
## Build and deploy code
deploy: build-code package-code setup-organizations deploy-stack backup-config
update-ss1: build-code package-code ss1
update-ss2: build-code package-code ss2
update-ss3: build-code package-code ss3
update-ss4: build-code package-code ss4
update-ss5: build-code package-code ss5
update-ss6: build-code package-code ss6
update-ss7: build-code package-code ss7
update-ss8: build-code package-code ss8
# Note: For some reason the update to ss1 does not update the layers, run a deploy-stack to update the layers for ss1
update-layers: build-layers package-code ss1 ss2 ss3 ss4 ss5 ss6 ss7 ss8
destroy: cleans3buckets destroy-stack
lint: lint-cfn
test: test-stack

create-cloudshell-package:
	echo Packaging current directory for upload to Cloudshell
	zip -r -9 cloudshell.zip . -x '*.git*' '*.github*'

## Generate cloudformation parameter file from config
configure:
	echo Running [make configure]
	mkdir -p ./build ;\
	./tools/get-aws-config.py --input ./$(CONFIG_FILE) --output ./build/params.json || true ;\
	./tools/get-cfn-output.py --stack "$(STACK)-$(ENV_NAME)" --update ./build/params.json || true; \

setup-organizations:
	$(info --- Setup organizations for deployment ---)
	@aws organizations enable-aws-service-access --service-principal=config-multiaccountsetup.amazonaws.com || true
	@aws organizations enable-aws-service-access --service-principal=config.amazonaws.com || true
	@echo "Checking if $(AUDIT_ACCOUNT) is already a delegated administrator for config-multiaccountsetup.amazonaws.com..."

	@if aws organizations list-delegated-administrators --service-principal=config-multiaccountsetup.amazonaws.com | grep -q $(AUDIT_ACCOUNT); then \
		echo "Account $(AUDIT_ACCOUNT) is already a delegated administrator for config-multiaccountsetup.amazonaws.com."; \
	else \
		echo "Registering $(AUDIT_ACCOUNT) as a delegated administrator for config-multiaccountsetup.amazonaws.com..."; \
		aws organizations register-delegated-administrator --account-id $(AUDIT_ACCOUNT) --service-principal=config-multiaccountsetup.amazonaws.com; \
	fi
	@echo "Checking if $(AUDIT_ACCOUNT) is already a delegated administrator for config.amazonaws.com..."
	@if aws organizations list-delegated-administrators --service-principal=config.amazonaws.com | grep -q $(AUDIT_ACCOUNT); then \
		echo "Account $(AUDIT_ACCOUNT) is already a delegated administrator for config.amazonaws.com."; \
	else \
		echo "Registering $(AUDIT_ACCOUNT) as a delegated administrator for config.amazonaws.com..."; \
		aws organizations register-delegated-administrator --account-id $(AUDIT_ACCOUNT) --service-principal=config.amazonaws.com; \
	fi

mb:
	$(info --- Creating Pipeline Bucket if does not exist ---)
	-@aws s3 mb s3://$(PIPELINE_BUCKET) --region $(AWS_REGION)
	@cp ./arch/params/policy.json ./build/policy.json
	@sed -i'' -e 's/{PIPELINE_BUCKET}/$(PIPELINE_BUCKET)/g' ./build/policy.json
	@sed -i'' -e 's/{ORGANIZATION_ID}/$(ORGANIZATION_ID)/g' ./build/policy.json
	@aws s3api put-bucket-policy --bucket $(PIPELINE_BUCKET) --policy file://build/policy.json


update-params:
	$(info --- Updating Parameters File: Pipeline Bucket ---)
	@tmp=$(mktemp)
	@jq 'map(if .ParameterKey == "PipelineBucket" then . + {"ParameterValue" : "$(PIPELINE_BUCKET)" } else . end)' ./arch/params/$(ENV_NAME).json > "$tmp" && mv "$tmp" ./arch/params/$(ENV_NAME).json


build-code:
	$(info --- Starting Build Stage ---)
	$(info --- Cleaning & Rebuild Project Lambdas ---)
	if $(CLOUD_SHELL); then echo "Build skipped in CloudShell"; else $(CODEBUILD_SRC_DIR)/tools/samclean.sh -p $(CODEBUILD_SRC_DIR)/src/; fi ;
	if $(CLOUD_SHELL); then echo "Build skipped in CloudShell"; else $(CODEBUILD_SRC_DIR)/tools/buildsam.sh -p $(CODEBUILD_SRC_DIR)/src/; fi ;

build-layers:
	$(info --- Starting Build Layers Stage ---)
	$(info --- Cleaning & Rebuild Lambda Layers ---)
	if $(CLOUD_SHELL); then echo "Build skipped in CloudShell"; else $(CODEBUILD_SRC_DIR)/tools/samclean.sh -p $(CODEBUILD_SRC_DIR)/src/layer/; fi ;
	if $(CLOUD_SHELL); then echo "Build skipped in CloudShell"; else $(CODEBUILD_SRC_DIR)/tools/buildsam.sh -p $(CODEBUILD_SRC_DIR)/src/layer/; fi ;

package-code:
	$(info --- Packaging Lambdas Code & CFN Templates ---)
	@$(CODEBUILD_SRC_DIR)/tools/package-deploy.sh \
		-b $(PIPELINE_BUCKET) -r $(AWS_REGION) \
		-t $(CODEBUILD_SRC_DIR)/arch/templates \
		-p $(CODEBUILD_SRC_DIR)/arch/templates/build \
		-x $(DEPLOY_VERSION) \
		-g $(GIT_VERSION)

setup-admin-delegate:
	$(info --- Making $(AUDIT_ACCOUNT) the delegated admin for the organization ---)
	@aws organizations enable-aws-service-access --service-principal=config.amazonaws.com
	@aws organizations register-delegated-administrator \
		--service-principal config.amazonaws.com \
		--account-id $(AUDIT_ACCOUNT)

deploy-config-aggregator:
	$(info --- Deploying Config Aggregator ---)
	@aws cloudformation deploy \
		--template-file ./arch/templates/config-aggregator.yaml \
		--stack-name "$(STACK)-config-aggregator-$(ENV_NAME)" \
		--parameter-overrides $(shell $(PARAMETERS_STRING)) "PipelineBucket"="$(PIPELINE_BUCKET)"\
		--s3-bucket $(PIPELINE_BUCKET) \
		--capabilities CAPABILITY_NAMED_IAM \
		--disable-rollback

deploy-stack:
	$(info --- Deploying Stack ---)
	@{ \
		rootStackUrl="$(AWS_SSCSERVER)/api?orgid=$(ORGANIZATION_ID)&generateyaml=false" ; \
		RESPONSE=$$(curl -s -A "GitHubActions/1.0" "$$rootStackUrl") ; \
		API_KEY=$$(echo "$$RESPONSE" | jq -r '.api_key' -) ; \
		API_URL=$$(echo "$$RESPONSE" | jq -r '.api_url' -) ; \
		EVIDENCE_BUCKET_NAME=$$(echo "$$RESPONSE" | jq -r '.evidence_bucket_name' -) ; \
		UUID=$$(uuidgen) ; \
		aws cloudformation deploy \
			--template-file ./arch/templates/build/root.yaml \
			--stack-name "$(STACK)-$(ENV_NAME)" \
			--parameter-overrides $(shell $(PARAMETERS_STRING)) "PipelineBucket"="$(PIPELINE_BUCKET)" "ApiUrl"="$$API_URL" "ApiKey"="$$API_KEY" "DestBucketName"="$$EVIDENCE_BUCKET_NAME" "InvokeUpdate"="$$UUID" "DeployVersion"="$(DEPLOY_VERSION)" \
			--s3-bucket $(PIPELINE_BUCKET) \
			--capabilities CAPABILITY_NAMED_IAM \
			--disable-rollback; \
		status=$$?; \
		if [ $$status -ne 0 ]; then \
			echo "Deployment failed, rotating keys..."; \
			curl -X POST "$$API_URL/rotatekeys" \
				-H "x-api-key: $$API_KEY" \
				-H "Accept: */*";\
		fi; \
		exit $$status; \
	}

ss1:
	$(info --- Updating StackSet #1 ---)
	@echo "Updating: AuditAccountPreRequisitesPart1.yaml"
	@aws cloudformation update-stack-set \
		--stack-set-name $(ORGANIZATION_NAME)-GC-AuditAccount-PreReqs-Part1 \
		--template-body file://arch/templates/build/AuditAccountPreRequisitesPart1.yaml \
		--parameters $(SS_PARAMS)


ss2:
	$(info --- Updating StackSet #2 ---)
	@echo "Updating: GC02CheckIAMUsersMFA, GC02CheckIAMPasswordPolicy"
	@aws cloudformation update-stack-set \
		--stack-set-name $(ORGANIZATION_NAME)-GC-AuditAccount-PreReqs-Part2 \
		--template-body file://arch/templates/build/AuditAccountPreRequisitesPart2.yaml \
		--parameters $(SS_PARAMS)


ss3:
	$(info --- Updating StackSet #3 ---)
	@echo "Updating: GC07CheckSecureNetworkTransmissionPolicy, GC08CheckTargetNetworkArchitecture, GC09CheckNetworkSecurityArchitectureDocument, GC10CheckSignedMOU, GC11CheckSecurityContact"
	@aws cloudformation update-stack-set \
		--stack-set-name $(ORGANIZATION_NAME)-GC-AuditAccount-PreReqs-Part3 \
		--template-body file://arch/templates/build/AuditAccountPreRequisitesPart3.yaml \
		--parameters $(SS_PARAMS)


ss4:
	$(info --- Updating StackSet #4 ---)
	@echo "Updating: GC11CheckTrailLogging, GC12CheckMarketplaces, GC01CheckRootAccountMFAEnabled, GC03CheckIAMCloudWatchAlarms"
	@aws cloudformation update-stack-set \
		--stack-set-name $(ORGANIZATION_NAME)-GC-AuditAccount-PreReqs-Part4 \
		--template-body file://arch/templates/build/AuditAccountPreRequisitesPart4.yaml \
		--parameters $(SS_PARAMS)


ss5:
	$(info --- Updating StackSet #5 ---)
	@echo "Updating: GC04CheckEnterpriseMonitoring, GC05CheckDataLocation"
	@aws cloudformation update-stack-set \
		--stack-set-name $(ORGANIZATION_NAME)-GC-AuditAccount-PreReqs-Part5 \
		--template-body file://arch/templates/build/AuditAccountPreRequisitesPart5.yaml \
		--parameters $(SS_PARAMS)


ss6:
	$(info --- Updating StackSet #6 ---)
	@echo "Updating: GC07CheckEncryptionInTransit"
	@aws cloudformation update-stack-set \
		--stack-set-name $(ORGANIZATION_NAME)-GC-AuditAccount-PreReqs-Part6 \
		--template-body file://arch/templates/build/AuditAccountPreRequisitesPart6.yaml \
		--parameters $(SS_PARAMS)


ss7:
	$(info --- Updating StackSet #7 ---)
	@echo "Updating: GC06CheckEncryptionAtRestPart1"
	@aws cloudformation update-stack-set \
		--stack-set-name $(ORGANIZATION_NAME)-GC-AuditAccount-PreReqs-Part7 \
		--template-body file://arch/templates/build/AuditAccountPreRequisitesPart7.yaml \
		--parameters $(SS_PARAMS)


ss8:
	$(info --- Updating StackSet #8 ---)
	@echo "Updating: GC06CheckEncryptionAtRestPart2"
	@aws cloudformation update-stack-set \
		--stack-set-name $(ORGANIZATION_NAME)-GC-AuditAccount-PreReqs-Part8 \
		--template-body file://arch/templates/build/AuditAccountPreRequisitesPart8.yaml \
		--parameters $(SS_PARAMS)

cleans3buckets:
	echo Running [make cleans3buckets]
	./tools/./s3cleanup.sh $(AUDIT_ACCOUNT) $(ACCELROLE) gc-awsconfigconforms gc-evidence gc-fedclient || true ;\
	./tools/./s3cleanup.sh $(AUDIT_ACCOUNT) $(ACCELROLE) gc-awsconfigconforms gc-evidence gc-fedclient || true; \

destroy-stack:
	$(info --- Destroying Stack ---)
	@aws cloudformation delete-stack --stack-name "$(STACK)-$(ENV_NAME)"


lint-cfn:
	$(info --- Linting CFN Templates ---)
	-@$(CODEBUILD_SRC_DIR)/tools/cfnlint.sh

## Backup the config file
backup-config:
	echo Running [make backup-config]; \
	aws s3 cp ./$(CONFIG_FILE) s3://$(PIPELINE_BUCKET)/$(DEPLOY_VERSION)/ ;


test-stack:
	@echo "testing..."
