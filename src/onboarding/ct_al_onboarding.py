#
# Copyright Alert Logic, Inc.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
import boto3, json, time, base64, os
import logging
import almdrlib
import requests

WAIT_TIME = 5   # Wait for 5 seconds
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
almdrlib.set_logger('almdrlib', logging.INFO)

global_endpoint = os.environ.get('AlertLogicApiEndpoint', 'production').lower()

session = boto3.Session()
sns_name = 'aws-controltower-AllConfigNotifications'

sqs_policy_template = {
  "Version": "2012-10-17",
  "Id": "SQSDefaultPolicy",
  "Statement": [
    {
      "Sid": "AlertLogicSNS",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "SQS:SendMessage",
      "Resource": "TBD",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "TBD"
        }
      }
    }
  ]
}

MASTER_TYPE = 'MASTER'
SECURITY_SETUP_TYPE = 'SECURITY_SETUP'
CENTRAL_ROLE_TYPE = 'CENTRAL_ROLE'

stackset_params_map = {
    MASTER_TYPE: [
        'OrgId',
        'SecurityAccount',
        'LogArchiveAccount',
        'AlertLogicCustomerId',
        'MasterAccount',
        'MasterRegion',
        'AlertLogicCentralizedRoleArn',
        'AlertLogicSourceRoleTemplateUrl',
        'FullRegionCoverage',
        'CoverageTags',
        'AlertLogicDeploymentMode',
        'SourceBucket',
        'AlertLogicApiEndpoint'
        ],
    SECURITY_SETUP_TYPE: [
        'OrgId',
        'AlertLogicCustomerId',
        'TargetRegion',
        'SourceBucket',
        'FullRegionCoverage',
        'AlertLogicApiEndpoint'
        ]
}


def assume_role(aws_account_number, role_name, external_id):
    '''
    Assumes the provided role in each account and returns a session object
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call
    :return: Session object for the specified AWS Account and Region
    '''
    try:
        sts_client = boto3.client('sts')
        partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
        response = sts_client.assume_role(
            RoleArn='arn:{}:iam::{}:role/{}'.format(
                partition, aws_account_number, role_name),
            RoleSessionName=str(aws_account_number + '-' + role_name),
            ExternalId=external_id
        )
        sts_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        LOGGER.info(
                "Assumed session for {} - {}.".format(
                    aws_account_number, role_name)
                )
        return sts_session

    except Exception as e:
        LOGGER.error("Could not assume role : {}".format(e))
        return False


def cfnresponse_send(
        event, context, responseStatus, responseData,
        physicalResourceId=None, noEcho=False):
    '''
    function to signal CloudFormation custom resource
    '''
    responseUrl = event['ResponseURL']
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData
    json_responseBody = json.dumps(responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }
    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        LOGGER.info("CFN Response Status code: " + response.reason)
    except Exception as e:
        LOGGER.info("CFN Response Failed: " + str(e))


def create_stack_set(target_session, region, stackset_name, stackset_url, parameter_list, admin_role, exec_role, capabilities_list):
    '''
    Crate Stack Set function.
    '''
    try:
        cfn_client = target_session.client('cloudformation')
        result = cfn_client.create_stack_set(
            StackSetName=stackset_name,
            TemplateURL=stackset_url,
            Parameters=parameter_list,
            AdministrationRoleARN=admin_role,
            ExecutionRoleName=exec_role,
            Capabilities=capabilities_list
        )
        return result
    except Exception as e:
        if e.response['Error']['Code'] == "NameAlreadyExistsException":
            LOGGER.info("StackSet {} already exists".format(stackset_name))
            return True
        else:
            LOGGER.error("StackSet error({}) : {}".format(stackset_name, e))
            return False


def get_secret(target_session, region, secret_name):
    '''
    Get Alert Logic API Credentials
    '''
    secret_client = target_session.client('secretsmanager')
    try:
        get_secret_value_response = secret_client.get_secret_value(
            SecretId=secret_name
        )
    except Exception as e:
        LOGGER.info(f"Get Secret Failed: {str(e)}")
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(
                    get_secret_value_response['SecretBinary']
                )
            return decoded_binary_secret


def get_output_value(results, account_id, region, name):
    output = results[account_id][region]
    for v in output:
        if v['OutputKey'] == name:
            return v['OutputValue']
    return None


def get_regions(master_region_name, regions):
    '''
    Order regions with master region being the first one
    '''
    regions = [
        region.strip()
        for region in regions if region.strip() != master_region_name
    ]
    regions[:0] = [master_region_name]
    return regions


def dict_to_param_list(payload, type=MASTER_TYPE):
    stackset_param_list = []
    if type not in stackset_params_map:
        return stackset_param_list

    keys = stackset_params_map[type]
    for key, value in payload.items():
        if key in keys:
            keyDict = {}
            keyDict['ParameterKey'] = key
            if isinstance(value, list):
                keyDict['ParameterValue'] = ','.join(value)
            else:
                keyDict['ParameterValue'] = value
            stackset_param_list.append(keyDict)

    return stackset_param_list


def get_ci_role_cft_url(target_session, role_type, region, event):
    '''
    Get Alert Logic's IAM Role CloudFormation template URL
    from Themis service
    '''
    secret_name = event['ResourceProperties']['Secret']
    al_credentials = get_secret(target_session, region, secret_name)
    if not al_credentials:
        raise ValueError(f"Invalid Secret: {secret_name}")

    auth = json.loads(al_credentials)
    LOGGER.info(f"Initializing client for {auth['ALAccessKey']} using {global_endpoint} endpoint")
    themis_client = almdrlib.client(
            'themis',
            access_key_id=auth['ALAccessKey'],
            secret_key=auth['ALSecretKey'],
            global_endpoint=global_endpoint
        )

    response = themis_client.get_role(
            account_id=event['ResourceProperties']['AlertLogicCustomerId'],
            platform_type='aws',
            role_type=role_type,
            role_version='latest'
        ).json()

    ci_x_account_ct_cft_url = response['cft']['s3_url']
    LOGGER.info(f"Alert Logic Cross Account StackSet URL: {ci_x_account_ct_cft_url}")
    return ci_x_account_ct_cft_url


def get_protected_accounts(included_ou_list, excluded_ou_list, master_account, core_accounts):
    '''
    Get List accounts to protect
    '''
    accounts = set()
    try:
        kwargs = {}
        orgs_client = session.client('organizations')
        if 'ALL' in included_ou_list:
            while True:
                response = orgs_client.list_accounts(**kwargs)
                accounts.update([
                        account['Id']
                        for account in response['Accounts'] if account['Status'] == 'ACTIVE' and account['Id'] != master_account
                    ])
                if 'NextToken' not in response:
                    break
                kwargs['NextToken'] = response['NextToken']
        else:
            for parent_id in included_ou_list:
                kwargs['ParentId'] = parent_id
                while True:
                    response = orgs_client.list_accounts_for_parent(**kwargs)
                    accounts.update([
                            account['Id']
                            for account in response['Accounts'] if account['Status'] == 'ACTIVE'and account['Id'] != master_account
                        ])
                    if 'NextToken' not in response:
                        break
                    kwargs['NextToken'] = response['NextToken']

        return list(accounts.difference(core_accounts))
    except Exception as e:
        LOGGER.error("Could not list accounts for parent : {}".format(e))
        return False


def create_stack_instance(
        target_session, stackset_name, org_id, accounts, regions,
        parameter_overrides=None,
        wait_for_completion=False,
        outputs=False,
        allow_failures=False):
    '''
    Create stackset in particular account + region
    '''
    try:
        cfn_client = target_session.client('cloudformation')
        LOGGER.debug(
            "Calling create_stack_instances... StackSetName={}, Accounts={}, Regions={}".format(
                stackset_name, accounts, regions)
            )
        kwargs = {
            'StackSetName': stackset_name,
            'Accounts': accounts,
            'Regions': regions
        }
        if parameter_overrides:
            kwargs['ParameterOverrides'] = parameter_overrides
        if allow_failures:
            kwargs['OperationPreferences'] = {'FailureTolerancePercentage': 100}

        LOGGER.info(f"Create stack instances parameters: {kwargs}")
        response = cfn_client.create_stack_instances(**kwargs)
        operation_id = response["OperationId"]
        LOGGER.debug(response)
        LOGGER.info(
                "Launched stackset instance {} for accounts {} in regions: {} with Operation id: {}".format(
                    stackset_name, accounts, regions, operation_id)
                )

        if not wait_for_completion:
            return True

        status = 'RUNNING'
        while(status == 'RUNNING'):
            time.sleep(WAIT_TIME)
            response = cfn_client.describe_stack_set_operation(
                OperationId=operation_id,
                StackSetName=stackset_name
                )
            status = response['StackSetOperation']['Status']
        if not outputs:
            return True

        result = {}
        for account in accounts:
            result[account] = {}
            account_session = assume_role(
                    account,
                    'AWSControlTowerExecution',
                    org_id)

            for region in regions:
                response = cfn_client.describe_stack_instance(
                        StackSetName=stackset_name,
                        StackInstanceAccount=account,
                        StackInstanceRegion=region)
                stack_id = response['StackInstance']['StackId']
                account_cfn_client = account_session.client('cloudformation')
                response = account_cfn_client.describe_stacks(
                        StackName=stack_id)
                result[account][region] = response['Stacks'][0]['Outputs']
        LOGGER.info(f"{stackset_name} Stackset Outputs: {result}")
        return True, result
    except Exception as e:
        LOGGER.error("Could not create stackset instance : {}".format(e))
        return False


def security_account_setup_handler(target_session, account, region, event):
    '''
    Configure Security Account Infrastructure by deploying Security setup stackset instance
    :param target_session: boto3 session object
    :param account: Control Tower master account id
    :param region: Master region
    :event CFT Custom Resource event
    :return: Registration SNS Topic
    '''
    secret_name = event['ResourceProperties']['Secret']
    al_credentials = get_secret(target_session, region, secret_name)
    if not al_credentials:
        raise ValueError(f"Invalid Secret: {secret_name}")

    org_id = event['ResourceProperties']['OrgId']
    security_account = event['ResourceProperties']['SecurityAccount']
    stackset_name = event['ResourceProperties']['SecurityAccountSetupStackSetName']
    stackset_url = event['ResourceProperties']['SecurityAccountSetupStackSetTemplateUrl']
    stackset_param_list = dict_to_param_list(event['ResourceProperties'], type=SECURITY_SETUP_TYPE)
    auth = json.loads(al_credentials)
    stackset_param_list.extend([
        {
            "ParameterKey": "AlertLogicAPIAccessKey",
            "ParameterValue": auth['ALAccessKey']
        },
        {
            "ParameterKey": "AlertLogicAPISecretKey",
            "ParameterValue": auth['ALSecretKey']
        }
    ])
    stackset_result = create_stack_set(
        target_session=target_session,
        region=region,
        stackset_name=stackset_name,
        stackset_url=stackset_url,
        parameter_list=stackset_param_list,
        admin_role='arn:aws:iam::' + account + ':role/service-role/AWSControlTowerStackSetRole',
        exec_role='AWSControlTowerExecution',
        capabilities_list=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND']
        )
    if not stackset_result:
        raise Exception(f"Failed to create {stackset_name} StackSet: {stackset_result}")

    create_instance_result, outputs = create_stack_instance(
        target_session=target_session,
        stackset_name=stackset_name,
        org_id=org_id,
        accounts=[security_account],
        regions=[region],
        wait_for_completion=True,
        outputs=True
        )
    output = outputs[security_account][region]
    for v in output:
        if v['OutputKey'] == 'RegistrationSNS':
            registration_sns = v['OutputValue']
        if v['OutputKey'] == 'Secret':
            secret = v['OutputValue']
    LOGGER.info(f"RegistrationSNS: {registration_sns}")
    return registration_sns, secret


def guardduty_setup_handler(target_session, org_id, master_account, master_region, accounts, regions, event):
    '''
    Configure Alert Logic's GuardDuty integration by deploying GuardDuty Collector stackset instances
    :param target_session: boto3 session object
    :param master_account: Control Tower master account id
    :param master_region: Master region
    :param accounts: List of accounts to deploy the GuardDuty integration
    :param regions: List of regions to deploy the GuardDuty integration
    :event CFT Custom Resource event
    :return:
    '''
    secret_name = event['ResourceProperties']['Secret']
    al_credentials = get_secret(target_session, master_region, secret_name)
    if not al_credentials:
        raise ValueError(f"Invalid Secret: {secret_name}")

    if event['ResourceProperties']['EnableGuardDutyIntegration'].lower() != 'true':
        LOGGER.info("Enable GuardDuty Integration is not requested.")
        return

    stackset_name = event['ResourceProperties']['AlertLogicGuardDutyCollectorStackSetName']
    org_id = event['ResourceProperties']['OrgId']
    stackset_name = event['ResourceProperties']['AlertLogicGuardDutyCollectorStackSetName']
    stackset_url = event['ResourceProperties']['AlertLogicGuardDutyCollectorTemplateUrl']
    auth = json.loads(al_credentials)
    stackset_param_list = [
            {
                "ParameterKey": "AccessKeyId",
                "ParameterValue": auth['ALAccessKey']
            },
            {
                "ParameterKey": "SecretKey",
                "ParameterValue": auth['ALSecretKey']
            }
        ]

    stackset_result = create_stack_set(
            target_session=target_session,
            region=master_region,
            stackset_name=stackset_name,
            stackset_url=stackset_url,
            parameter_list=stackset_param_list,
            admin_role='arn:aws:iam::' + master_account + ':role/service-role/AWSControlTowerStackSetRole',
            exec_role='AWSControlTowerExecution',
            capabilities_list=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND']
        )
    if not stackset_result:
        raise Exception(f"Failed to create {stackset_name} StackSet: {stackset_result}")

    create_stack_instance(
            target_session=target_session,
            stackset_name=stackset_name,
            org_id=org_id,
            accounts=accounts,
            regions=regions,
            allow_failures=True
        )


def lambda_handler(event, context):
    try:
        LOGGER.info('Lambda Handler - Start')
        LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))

        if event['RequestType'] in ['Create', 'Update']:
            org_id = event['ResourceProperties']['OrgId']
            log_archive_account = event['ResourceProperties']['LogArchiveAccount']
            security_account = event['ResourceProperties']['SecurityAccount']
            audit_account = event['ResourceProperties']['AuditAccount']
            region = str(context.invoked_function_arn).split(":")[3]
            account = str(context.invoked_function_arn).split(":")[4]

            registration_sns, secret = security_account_setup_handler(session, account, region, event)

            # Create and deploy Central CloudTrail Log Collection StackSet
            # to Log Archive and Audit accounts
            # TODO: Move this code to its own function
            ci_x_account_ct_cft_url = get_ci_role_cft_url(session, 'ci_x_account_ct', region, event)

            stackset_name = event['ResourceProperties']['CentralizedRoleStackSetName']
            stackset_result = create_stack_set(
                target_session=session,
                region=region,
                stackset_name=stackset_name,
                stackset_url=ci_x_account_ct_cft_url,
                parameter_list=[
                        {
                            'ParameterKey': 'ExternalId',
                            'ParameterValue': event['ResourceProperties']['AlertLogicCustomerId']
                        }
                    ],
                admin_role='arn:aws:iam::' + account + ':role/service-role/AWSControlTowerStackSetRole',
                exec_role='AWSControlTowerExecution',
                capabilities_list=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND']
                )
            if not stackset_result:
                raise Exception(f"Failed to create {stackset_name} StackSet")

            create_result, outputs = create_stack_instance(
                    target_session=session,
                    stackset_name=stackset_name,
                    org_id=org_id,
                    accounts=[log_archive_account, audit_account],
                    regions=[region],
                    wait_for_completion=True,
                    outputs=True
                    )
            ci_x_account_role_arn = get_output_value(outputs, log_archive_account, region, 'RoleARN')
            LOGGER.info(f"Log Archive Account ALCentralizedRoleArn: {ci_x_account_role_arn}")

            ci_x_audit_account_role_arn = get_output_value(outputs, audit_account, region, 'RoleARN')
            LOGGER.info(f"Audit Account ALCentralizedRoleArn: {ci_x_audit_account_role_arn}")

            #
            # Create Control Tower Master account StackSet
            #
            mode = event['ResourceProperties']['AlertLogicDeploymentMode']
            if mode == 'Automatic':
                role_type = 'ci_full'
            else:
                role_type = 'ci_manual'
            ci_cft_url = get_ci_role_cft_url(session, role_type, region, event)
            stackset_param_list = dict_to_param_list(event['ResourceProperties'])

            # Update stackset parameters to include:
            # x-account cloudtrail access role
            # Alert Logic third-party role
            # Registration SNS Topic
            # Alert Logic Secret ARN in Security Account
            stackset_param_list.extend([
                    {
                        "ParameterKey": "AlertLogicSourceRoleTemplateUrl",
                        "ParameterValue": ci_cft_url
                    },
                    {
                        "ParameterKey": "AlertLogicCentralizedRoleArn",
                        "ParameterValue": ci_x_account_role_arn
                    },
                    {
                        "ParameterKey": "RegistrationSNS",
                        "ParameterValue": registration_sns
                    },
                    {
                        "ParameterKey": "Secret",
                        "ParameterValue": secret
                    }
                ])

            stackset_name = event['ResourceProperties']['StackSetName']
            LOGGER.info(f"Creating {stackset_name} stackset with {stackset_param_list} parameters")
            stackset_result = create_stack_set(
                    target_session=session,
                    region=region,
                    stackset_name=stackset_name,
                    stackset_url=event['ResourceProperties']['StackSetUrl'],
                    parameter_list=stackset_param_list,
                    admin_role='arn:aws:iam::' + account + ':role/service-role/AWSControlTowerStackSetRole',
                    exec_role='AWSControlTowerExecution',
                    capabilities_list=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND']
                )

            if stackset_result:
                LOGGER.info("Adding stack instance for core accounts")

                # Create SecurityAccount stack instance first to ensure that
                # SNS Topic is present for other stack instances
                # to publish registration request
                core_accounts = set([security_account, log_archive_account, audit_account])
                accounts = list(core_accounts.difference({audit_account}))
                regions = get_regions(
                        region,
                        str(event['ResourceProperties']['TargetRegion']).split(",")
                    )

                # Deploy stackset to core accounts
                create_stack_instance(
                        target_session=session,
                        stackset_name=stackset_name,
                        org_id=org_id,
                        accounts=[audit_account],
                        regions=regions,
                        wait_for_completion=True
                    )

                # Deploy stackset to Log Archive account
                # Create stack instances for the rest of the accounts
                create_stack_instance(
                        target_session=session,
                        stackset_name=stackset_name,
                        org_id=org_id,
                        accounts=[log_archive_account],
                        regions=regions,
                        parameter_overrides=[
                                {
                                    "ParameterKey": "AlertLogicCentralizedRoleArn",
                                    "ParameterValue": ci_x_audit_account_role_arn
                                }
                            ],
                        wait_for_completion=True
                    )

                accounts.remove(log_archive_account)
                # Create accounts for specified OUs, if any
                protected_accounts = get_protected_accounts(
                    included_ou_list=event['ResourceProperties']['IncludeOrganizationalUnits'],
                    excluded_ou_list=event['ResourceProperties']['ExcludeOrganizationalUnits'],
                    master_account=account,
                    core_accounts=core_accounts
                    )
                accounts.extend(protected_accounts)
                create_stack_instance(
                        target_session=session,
                        stackset_name=stackset_name,
                        org_id=org_id,
                        accounts=accounts,
                        regions=regions,
                        allow_failures=True
                    )
            LOGGER.info("StackSet status : {}".format(stackset_result))

            # Deploy GuardDuty Integration
            guardduty_setup_handler(
                    target_session=session,
                    org_id=org_id,
                    master_account=account,
                    master_region=region,
                    accounts=protected_accounts + list(core_accounts),
                    regions=regions,
                    event=event
                    )

        response_data = {}
        response_data["event"] = event
        cfnresponse_send(
                event, context,
                'SUCCESS', response_data, "CustomResourcePhysicalID")

        LOGGER.info('Lambda Handler - End')
    except Exception as e:
        LOGGER.exception(e)
        response_data = {}
        response_data["Status"] = str(e)
        cfnresponse_send(
                event, context,
                'FAILED', response_data, "CustomResourcePhysicalID")
