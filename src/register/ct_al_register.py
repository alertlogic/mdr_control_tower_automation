# Copyright Alert Logic, Inc. All Rights Reserved.
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

import boto3, json, time, sys, os, base64
import logging
import requests
import almdrlib
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
almdrlib.set_logger('almdrlib', logging.INFO)

global_endpoint = os.environ.get('AlertLogicApiEndpoint', 'production').lower()
region_coverage = os.environ['FullRegionCoverage'].lower() == 'true'
regions = str(os.environ['TargetRegion']).replace(" ", "").split(",")

session = boto3.Session()


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


def get_secret(target_session, region, secret_name):
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


def get_account_name(target_session, account_id):
    return account_id

    organizations_client = target_session.client('organizations')
    try:
        response = organizations_client.describe_account(
            AccountId=account_id
            )
        return response['Account']['Name']
    except Exception as e:
        LOGGER.info(f"Describe Account Failed: {str(e)}")
        return account_id


def get_deployment(client, al_account_id, aws_account_id):
    try:
        deployments = client.list_deployments(account_id=al_account_id).json()
        for deployment in deployments:
            platform = deployment['platform']
            if platform['type'] == 'aws' and platform['id'] == aws_account_id:
                LOGGER.info(f"Alert Logic Deployment ID: {deployment['id']}")
                return deployment

        LOGGER.info("Account {} is not protected by Alert Logic MDR".format(
                aws_account_id
            ))
        return None
    except Exception as e:
        LOGGER.exception(f"Failed to list deployments. Error: {str(e)}")
        return None


def get_policy_id(client, al_account_id):
    try:
        policies = client.list_policies(account_id=al_account_id).json()
        for policy in policies:
            if policy['name'] in ['Professional', 'Enterprise']:
                LOGGER.info(f"Policy ID for {al_account_id} is {policy['id']}")
                return policy['id']

        LOGGER.Error(f"Cannot find 'Professional' policy id")
        return None
    except Exception as e:
        LOGGER.exception(f"Failed to list policies. Error: {str(e)}")
        return None


def get_scope(policy_id, scope):
    # Get protection policy ID
    if not policy_id:
        return []

    return [
            {
                'key': asset['key'],
                'type': asset['type'],
                'policy': {
                    'id': policy_id
                }
            }
            for asset in scope
        ]


def handle_update_notification(session, context, sns_event):
    if region_coverage:
        return

    try:
        al_credentials = get_secret(
                session,
                str(context.invoked_function_arn).split(":")[4],
                os.environ['Secret']
            )
        if not al_credentials:
            LOGGER.error("Unable to retrieve the AlertLogic API credentials")
            return

        # Create Alert Logic Deployment Credentials
        auth = json.loads(al_credentials)
        al_session = almdrlib.Session(
                account_id=auth['ALCID'],
                access_key_id=auth['ALAccessKey'],
                secret_key=auth['ALSecretKey'],
                global_endpoint=global_endpoint
            )

        deployments_client = al_session.client('deployments')
        deployment = get_deployment(
            deployments_client,
            auth['ALCID'],
            sns_event['account_id'])
        if not deployment:
            LOGGER.info("Deployment {} for customer {} not found.".format(
                    sns_event['account_id'], auth['ALCID']
                ))
            return

        # Get protection policy ID
        policy_id = get_policy_id(
                al_session.client('policies'),
                auth['ALCID']
                )
        if not policy_id:
            return

        scope = get_scope(policy_id=policy_id, scope=sns_event['scope'])
        for asset in scope:
            if asset not in deployment['scope']['include']:
                deployment['scope']['include'].append(asset)

        result = deployments_client.update_deployment(
                account_id=auth['ALCID'],
                deployment_id=deployment['id'],
                scope=deployment['scope'],
                version=deployment['version']
            )
        LOGGER.info("Updated {} deployment protection scope: {}".format(
            deployment['name'], result.json()))

    except Exception as e:
        LOGGER.exception(e)


def handle_create_notification(
        session, context, sns_event, include_scope, response_data):
    try:
        al_credentials = get_secret(
                session,
                str(context.invoked_function_arn).split(":")[4],
                os.environ['Secret']
            )
        if not al_credentials:
            LOGGER.error("Unable to retrieve the AlertLogic API credentials")
            return cfnresponse_send(
                    sns_event, context, 'FAILED',
                    response_data, "CustomResourcePhysicalID"
                )

        # Create Alert Logic Deployment Credentials
        auth = json.loads(al_credentials)
        al_session = almdrlib.Session(
                account_id=auth['ALCID'],
                access_key_id=auth['ALAccessKey'],
                secret_key=auth['ALSecretKey'],
                global_endpoint=global_endpoint
            )

        account_id = sns_event['ResourceProperties']['CID']
        deployments_client = al_session.client('deployments')
        deployment = get_deployment(
                deployments_client,
                auth['ALCID'],
                account_id
            )
        if not deployment:
            # Deployment doesn't exist. Create new deployment
            credentials_client = al_session.client('credentials')
            response = credentials_client.create_credential(
                account_id=account_id,
                name=f"{account_id}-linked-role",
                secrets={
                    'type': 'aws_iam_role',
                    'arn': sns_event['ResourceProperties']['ALSourceRoleArn']
                }).json()

            cred_id = response['id']
            LOGGER.info(f"AlertLogic Linked Account Cred Id: {cred_id}")

            # Create Alert Logic Cross Account Credentials
            response = credentials_client.create_credential(
                account_id=account_id,
                name=f"{account_id}-sqs-role",
                secrets={
                    'type': 'aws_iam_role',
                    'arn': sns_event['ResourceProperties']['ALCentralizedRoleArn']
                }).json()
            cred_x_id = response['id']
            LOGGER.info(f"AlertLogic Cross Account Cred Id: {cred_x_id}")

            # Create Alert Logic Deployment
            aws_account_id = sns_event['ResourceProperties']['AccountId']
            mode = sns_event['ResourceProperties']['AlertLogicDeploymentMode']
            policy_id = get_policy_id(
                    al_session.client('policies'),
                    auth['ALCID']
                )

            response = deployments_client.create_deployment(
                    account_id=account_id,
                    credentials=[
                            {'id': cred_id, 'purpose': 'discover'},
                            {'id': cred_x_id, 'purpose': 'x-account-monitor'}
                        ],
                    mode=mode.lower(),
                    discover=True,
                    scan=True,
                    enabled=True,
                    name=get_account_name(session, aws_account_id),
                    platform={
                        'type': 'aws',
                        'id': aws_account_id
                    },
                    scope={
                        'include': get_scope(
                                policy_id=policy_id,
                                scope=include_scope
                            ),
                        'exclude': []
                    }
                )
            LOGGER.info(
                    "Created Alert Logic Deployment: {}".format(
                        json.dumps(response.json(), default=str)))
        else:
            # Deployment already exists.
            # Update the include scope of the existing deployment
            policy_id = get_policy_id(
                    al_session.client('policies'),
                    auth['ALCID']
                )
            scope = get_scope(policy_id=policy_id, scope=include_scope)
            for asset in scope:
                if asset not in deployment['scope']['include']:
                    deployment['scope']['include'].append(asset)

            result = deployments_client.update_deployment(
                    account_id=auth['ALCID'],
                    deployment_id=deployment['id'],
                    scope=deployment['scope'],
                    version=deployment['version']
                )
            LOGGER.info(f"Updated protection scope: {result.json()}")

        cfnresponse_send(
                sns_event, context, 'SUCCESS',
                response_data, "CustomResourcePhysicalID"
            )
    except Exception as e:
        LOGGER.exception(e)
        response_data = {}
        response_data["Status"] = str(e)
        cfnresponse_send(
                sns_event, context, 'FAILED',
                response_data, "CustomResourcePhysicalID"
            )


def lambda_handler(event, context):
    LOGGER.info('Lambda Handler - Start')
    LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))

    for record in event['Records']:
        sns_event = json.loads(record['Sns']['Message'])
        LOGGER.info('REQUEST RECEIVED: {}'.format(
            json.dumps(sns_event, default=str))
            )
        if sns_event['RequestType'] == 'Create':
            response_data = {}
            response_data["event"] = event
            include_scope = []
            if region_coverage:
                include_scope = [
                        {'key': f'/aws/{region}', 'type': 'region'}
                        for region in regions
                    ]
            handle_create_notification(
                session,
                context,
                sns_event,
                include_scope,
                response_data
            )
        elif sns_event['RequestType'] == 'UpdateScope':
            handle_update_notification(session, context, sns_event)
        else:
            LOGGER.warning("Unsupported event - skipping")
            if sns_event['ResourceType'] == 'AWS::CloudFormation::CustomResource':
                cfnresponse_send(
                    sns_event,
                    context,
                    'SUCCESS',
                    {'event': event},
                    "CustomResourcePhysicalID"
                )

    LOGGER.info('Lambda Handler - End')
