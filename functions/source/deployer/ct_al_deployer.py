#
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
import boto3, json, time, sys, os, base64, copy
import logging
import requests
import almdrlib
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
almdrlib.set_logger('almdrlib', logging.INFO)

session = boto3.Session()

global_endpoint = os.environ.get('AlertLogicApiEndpoint', 'production').lower()
region_coverage = os.environ['FullRegionCoverage'] == 'true'
coverage_tags = str(os.environ['CoverageTags']).replace(" ", "").split(",")


def get_secret(target_session, secret_name):
    region_name = str(secret_name).split(":")[3]

    secret_client = target_session.client('secretsmanager', region_name=region_name)
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
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret
            
            
def get_asset_key(region, type, id):
    return f'/aws/{region}/{type}/{id}'
    

def update_scope(scope, region, resource_type, resources, add=True, policy_id=None):
    for resource in resources:
        asset_key = get_asset_key(
                region,
                resource_type,
                resource.split(":")[5].split("/")[1]
            )
        for asset in scope:
            if asset['key'] == asset_key and not add:
                    scope.remove(asset)
                    break
                    
        if add:
            scope.append(
                    {
                        'key': asset_key,
                        'type': resource_type,
                        'policy': {
                            'id': policy_id
                        }
                    }
                )
    return scope
                            
                            
def get_policy_id(client, al_account_id):
    try:
        policies = client.list_policies(account_id=al_account_id).json()
        for policy in policies:
            if policy['name'] in ['Professional', 'Enterprise']:
                return policy['id']
        LOGGER.Error(f"Cannot find 'Professional' policy id")
        return None
    except Exception as e:
        LOGGER.exception(f"Failed to list policies. Error: {str(e)}")
        return None
    
    
def get_deployment(client, al_account_id, aws_account_id):
    try:
        deployments = client.list_deployments(account_id=al_account_id).json()
        for deployment in deployments:
            platform = deployment['platform']
            if platform['type'] == 'aws' and platform['id'] == aws_account_id:
                LOGGER.info(f"Alert Logic Deployment ID: {deployment['id']}")
                return deployment
          
        LOGGER.Info(f"Account {aws_account_id} is not protected by Alert Logic MDR")      
        return None
    except Exception as e:
        LOGGER.exception(f"Failed to list deployments. Error: {str(e)}")
        return None
    
    
def lambda_handler(event, context):
    LOGGER.info('Lambda Handler - Start')
    LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))
    
    if not region_coverage:
        if 'detail-type' in event and event['detail-type'] == 'Tag Change on Resource':
            LOGGER.info("Using Event Bus Handler")
            resource_type = event['detail']['resource-type']
            if not resource_type == 'vpc':
                LOGGER.warning("Tag changes on non supported resource, skipping")
                LOGGER.info('Lambda Handler - End')
                return
            
            account_id = event['account']
            region = event['region']
            
            # Get Alert Logic API Credentials
            al_credentials = get_secret(
                session,
                os.environ['secret'])
            if not al_credentials:
                LOGGER.error("Unable to retrieve the AlertLogic API credentials")
                LOGGER.info('Lambda Handler - End')
                return
            
            # Initialize session to Alert Logic backend
            auth = json.loads(al_credentials)
            al_session = almdrlib.Session(
                    account_id=auth['ALCID'],
                    access_key_id=auth['ALAccessKey'],
                    secret_key=auth['ALSecretKey'],
                    global_endpoint=global_endpoint
                )
                    
            # Create Alert Logic Deployment Object
            deployments_client = al_session.client('deployments')
            deployment = get_deployment(deployments_client, auth['ALCID'], account_id)
            if not deployment:
                LOGGER.info('Lambda Handler - End')
                return
            
            # Get protection policy ID
            policies_client = al_session.client('policies')
            policy_id = get_policy_id(
                    al_session.client('policies'),
                    auth['ALCID'])
            if not policy_id:
                LOGGER.info('Lambda Handler - End')
                return
            
            LOGGER.info(f"Current Include Scope: {deployment['scope']['include']}")
            for tag in coverage_tags:
                tag_key, tag_value = tag.split(':')
                if tag_key in event['detail']['changed-tag-keys']:
                    add_to_scope = event['detail']['tags'].get(tag_key) == tag_value
                    include_scope = update_scope(
                            deployment['scope']['include'],
                            region,
                            'vpc',
                            event['resources'],
                            policy_id=policy_id,
                            add=add_to_scope
                        )
            LOGGER.info(f"New Include Scope: {include_scope}")

            deployment['scope']['include'] = include_scope
            result = deployments_client.update_deployment(
                account_id=auth['ALCID'],
                deployment_id=deployment['id'],
                scope=deployment['scope'],
                version = deployment['version']
                )            
            LOGGER.info(f"Updated protection scope: {result.json()}")
        else:
            LOGGER.info('Invalid event type - skipping')
    else:
        LOGGER.info('Running in full region protection mode - skipping')
    LOGGER.info('Lambda Handler - End')
