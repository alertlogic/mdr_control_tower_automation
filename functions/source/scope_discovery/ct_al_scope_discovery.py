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
import boto3, json, os
import logging
import requests

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

session = boto3.Session()

def is_protected(asset, tags):
    for tag in asset['Tags']:
        if f"{tag['Key']}:{tag['Value']}" in tags:
            return True
    return False


def get_asset_key(region, type, id):
    return f'/aws/{region}/{type}/{id}'

def get_vpcs_scope(client, tags, scope=[], next_token=None):
    type = 'vpc'
    tag_keys = [v.split(':')[0] for v in tags.split(',')]
    Filters = [
                {
                    'Name': 'tag-key',
                    'Values': tag_keys
                }
            ]
    kwargs = {'Filters': Filters, 'MaxResults': 100}
    if next_token:
        kwargs['NextToken'] = NextToken
    
    response = client.describe_vpcs(**kwargs)

    scope.extend(
        [
            {
                'key': get_asset_key(session.region_name, type, vpc['VpcId']),
                'type': type
            }
            for vpc in response['Vpcs'] if is_protected(vpc, tags)
        ]
    )
    if 'NextToken' in response:
        return get_vpcs_scope(
            scope, client, tags, scope, response['NextToken'])
    else:
        return scope


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


def lambda_handler(event, context):
    try:
        LOGGER.info(f'Lambda Handler - Start')
        LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))

        if event['RequestType'] == 'Create':
            if event['ResourceProperties']['FullRegionCoverage'].lower() != 'true':
                client = session.client('ec2')

                tags = event['ResourceProperties']['CoverageTags']
                scope = get_vpcs_scope(
                    client,
                    event['ResourceProperties']['CoverageTags']
                )

                LOGGER.info(f'Protection Scope: {scope}')
                topic_arn = event['ResourceProperties']['RegistrationSNS']
                client = session.client('sns', region_name = topic_arn.split(":")[3])
                response = client.publish(
                    TopicArn=topic_arn,
                    Message=json.dumps({
                        'RequestType': 'UpdateScope',
                        'scope': scope,
                        'account_id': str(context.invoked_function_arn).split(":")[4]
                    })
                )
            else:
                LOGGER.info("Running in full region coverage mode. Skipping scope discovery.")
        else:
            LOGGER.info("Unsupported event. Skipping scope discovery.")

        response_data = {}
        response_data['event'] = event
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
