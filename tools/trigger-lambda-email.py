#!/usr/bin/env python3
"""
Manually trigger the Lambda function for a specific S3 email object.
This script simulates the S3 event that would normally trigger the Lambda function.
"""

import boto3
import json
import argparse
import sys
import os

def create_s3_event(bucket_name, object_key):
    """
    Create a mock S3 event structure that mimics the event Lambda would receive.
    
    Args:
        bucket_name: S3 bucket name
        object_key: S3 object key (path to the email object)
        
    Returns:
        Dictionary containing the S3 event structure
    """
    return {
        "Records": [
            {
                "eventVersion": "2.1",
                "eventSource": "aws:s3",
                "awsRegion": "us-east-1",
                "eventTime": "2023-01-01T00:00:00.000Z",
                "eventName": "ObjectCreated:Put",
                "userIdentity": {"principalId": "MANUAL_TRIGGER"},
                "requestParameters": {"sourceIPAddress": "127.0.0.1"},
                "responseElements": {
                    "x-amz-request-id": "manual-request",
                    "x-amz-id-2": "manual-trigger"
                },
                "s3": {
                    "s3SchemaVersion": "1.0",
                    "configurationId": "manual-trigger-event",
                    "bucket": {
                        "name": bucket_name,
                        "ownerIdentity": {"principalId": "MANUAL_TRIGGER"},
                        "arn": f"arn:aws:s3:::{bucket_name}"
                    },
                    "object": {
                        "key": object_key,
                        "size": 0,
                        "eTag": "manual-trigger",
                        "versionId": None,
                        "sequencer": "manual-trigger"
                    }
                }
            }
        ]
    }

def trigger_lambda_with_s3_object(bucket_name, object_key, lambda_function_name=None):
    """
    Trigger the Lambda function with a specific S3 object.
    
    Args:
        bucket_name: S3 bucket name
        object_key: S3 object key (path to the email object)
        lambda_function_name: Optional Lambda function name. If not provided, it will try to find it.
    """
    try:
        # Check if the S3 object exists first
        s3 = boto3.client('s3')
        try:
            s3.head_object(Bucket=bucket_name, Key=object_key)
        except Exception as e:
            print(f"Error: S3 object s3://{bucket_name}/{object_key} doesn't exist or you don't have access to it.")
            print(f"Exception: {str(e)}")
            return False
        
        # Initialize the Lambda client
        lambda_client = boto3.client('lambda')
        
        # If lambda_function_name is not provided, try to find it
        if not lambda_function_name:
            lambda_function_name = find_lambda_function_for_s3_bucket(bucket_name)
            if not lambda_function_name:
                print("Error: Could not determine which Lambda function to invoke.")
                print("Please specify the Lambda function name using --lambda-function parameter.")
                return False
        
        # Create the S3 event
        event = create_s3_event(bucket_name, object_key)
        
        print(f"\nTriggering Lambda function '{lambda_function_name}' with S3 object: s3://{bucket_name}/{object_key}")
        
        # Invoke the Lambda function
        response = lambda_client.invoke(
            FunctionName=lambda_function_name,
            InvocationType='RequestResponse',  # Use 'Event' for asynchronous invocation
            Payload=json.dumps(event)
        )
        
        # Process the response
        status_code = response['StatusCode']
        
        if 'FunctionError' in response:
            print(f"Lambda execution failed with error: {response.get('FunctionError')}")
            if 'Payload' in response:
                payload = json.loads(response['Payload'].read())
                print(f"Error details: {json.dumps(payload, indent=2)}")
            return False
        
        if status_code == 200:
            print("Lambda function triggered successfully!")
            if 'Payload' in response:
                payload = json.loads(response['Payload'].read())
                print(f"Response: {json.dumps(payload, indent=2)}")
            return True
        else:
            print(f"Lambda function returned status code: {status_code}")
            if 'Payload' in response:
                payload = json.loads(response['Payload'].read())
                print(f"Response: {json.dumps(payload, indent=2)}")
            return False
            
    except Exception as e:
        print(f"Error triggering Lambda function: {str(e)}")
        return False

def find_lambda_function_for_s3_bucket(bucket_name):
    """
    Try to find a Lambda function that's configured as an S3 bucket trigger.
    
    Args:
        bucket_name: S3 bucket name
        
    Returns:
        Lambda function name if found, None otherwise
    """
    try:
        # Get bucket notification configuration
        s3 = boto3.client('s3')
        response = s3.get_bucket_notification_configuration(Bucket=bucket_name)
        
        # Check for Lambda function configurations
        if 'LambdaFunctionConfigurations' in response:
            for config in response['LambdaFunctionConfigurations']:
                if 'LambdaFunctionArn' in config:
                    lambda_arn = config['LambdaFunctionArn']
                    # Extract the function name from the ARN
                    function_name = lambda_arn.split(':')[-1]
                    print(f"Found Lambda function '{function_name}' configured for bucket '{bucket_name}'")
                    return function_name
        
        # If no Lambda function configuration is found, try listing Lambda functions
        # and check their environment variables and configurations
        print(f"No Lambda function found in bucket notification configuration for '{bucket_name}'")
        print("Searching Lambda functions with 's3' in their name or with S3 event source mapping...")
        
        lambda_client = boto3.client('lambda')
        functions = lambda_client.list_functions()['Functions']
        
        for function in functions:
            function_name = function['FunctionName']
            
            # Check if function name contains 's3', 'email', or 'mail'
            if any(keyword in function_name.lower() for keyword in ['s3', 'email', 'mail', 'phish']):
                print(f"Found potential Lambda function: {function_name}")
                return function_name
        
        print("No suitable Lambda function found.")
        return None
        
    except Exception as e:
        print(f"Error finding Lambda function: {str(e)}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trigger Lambda function with an S3 email object.")
    parser.add_argument("bucket_name", help="S3 bucket name")
    parser.add_argument("object_key", help="S3 object key (path to the email object)")
    parser.add_argument("--lambda-function", help="Lambda function name (optional)", default=None)
    
    args = parser.parse_args()
    
    trigger_lambda_with_s3_object(args.bucket_name, args.object_key, args.lambda_function)
