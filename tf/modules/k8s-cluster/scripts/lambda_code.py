import boto3
import json
import time
import os
import logging

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_env_var(var_name, is_required=True, default_value=None):
    """Helper function to get environment variables."""
    value = os.environ.get(var_name)
    if is_required and not value:
        error_msg = f"Environment variable {var_name} is required but not set."
        logger.error(error_msg)
        raise ValueError(error_msg)
    return value if value else default_value

def lambda_handler(event, context):
    logger.info(f"Event received: {json.dumps(event)}")

    # Get configuration from environment variables
    try:
        aws_region = get_env_var('REGION')
        control_plane_instance_id = get_env_var('CONTROL_PLANE_INSTANCE_ID')
        # This is the secret ID where the LATEST join token should be stored/refreshed
        join_command_latest_secret_id = get_env_var('JOIN_COMMAND_LATEST_SECRET_ID')
        # cluster_name = get_env_var('CLUSTER_NAME', is_required=False) # Available if needed
        # s3_log_bucket = get_env_var('S3_LOG_BUCKET', is_required=False) # Available if needed
    except ValueError as e:
        return {'statusCode': 500, 'body': str(e)}

    autoscaling = boto3.client('autoscaling', region_name=aws_region)
    ssm_client = boto3.client('ssm', region_name=aws_region)
    secrets_client = boto3.client('secretsmanager', region_name=aws_region)
    ec2_client = boto3.client('ec2', region_name=aws_region)

    # Check if the event is from SNS (for ASG lifecycle hook)
    if 'Records' in event and event['Records'][0].get('EventSource') == 'aws:sns':
        logger.info("SNS event detected, processing ASG lifecycle hook...")
        try:
            message_str = event['Records'][0]['Sns']['Message']
            message = json.loads(message_str)
            logger.info(f"SNS message content: {json.dumps(message)}")

            if message.get('LifecycleTransition') == 'autoscaling:EC2_INSTANCE_TERMINATING':
                instance_id = message.get('EC2InstanceId')
                lifecycle_hook_name = message.get('LifecycleHookName')
                asg_name = message.get('AutoScalingGroupName')

                if not all([instance_id, lifecycle_hook_name, asg_name]):
                    logger.error("Missing required fields in SNS message for termination event.")
                    # Optionally ABANDON if critical info is missing, or let it proceed.
                    return {'statusCode': 400, 'body': 'Missing required fields in SNS message.'}

                logger.info(f"Processing scale-down for instance: {instance_id} in ASG: {asg_name}")

                # Get node name (often private DNS name or a specific tag)
                # The original code used node_name from tags or private_ip. We'll try to get private DNS.
                node_name_to_drain = ""
                try:
                    instance_description = ec2_client.describe_instances(InstanceIds=[instance_id])
                    private_dns_name = instance_description['Reservations'][0]['Instances'][0].get('PrivateDnsName')
                    if private_dns_name:
                        node_name_to_drain = private_dns_name
                        logger.info(f"Instance {instance_id} has PrivateDnsName: {node_name_to_drain}")
                    else: # Fallback logic if PrivateDnsName is not the node name
                        tags = instance_description['Reservations'][0]['Instances'][0].get('Tags', [])
                        node_name_tag = next((tag['Value'] for tag in tags if tag['Key'].lower() == 'kubernetes.io/hostname'), None) # Common EKS tag
                        if node_name_tag:
                            node_name_to_drain = node_name_tag
                        else: # Final fallback if no suitable tag
                            private_ip = instance_description['Reservations'][0]['Instances'][0].get('PrivateIpAddress')
                            if private_ip: # This might not be unique or match k8s node name
                                node_name_to_drain = private_ip
                                logger.warning(f"Using private IP {private_ip} as node name for draining. This might not be the Kubernetes node name.")
                            else:
                                logger.error(f"Could not determine node name for instance {instance_id} to drain.")
                                raise Exception(f"Cannot determine node name for instance {instance_id}")
                except Exception as e_desc:
                    logger.error(f"Error describing instance {instance_id} to get node name: {str(e_desc)}")
                    # Abandon lifecycle action as we can't identify the node
                    autoscaling.complete_lifecycle_action(
                        LifecycleHookName=lifecycle_hook_name,
                        AutoScalingGroupName=asg_name,
                        LifecycleActionResult='ABANDON',
                        InstanceId=instance_id
                    )
                    return {'statusCode': 500, 'body': f"Error describing instance: {str(e_desc)}"}

                logger.info(f"Attempting to drain and delete Kubernetes node: {node_name_to_drain}")
                # Using /etc/kubernetes/admin.conf on the control plane
                drain_command = f"kubectl --kubeconfig=/etc/kubernetes/admin.conf drain {node_name_to_drain} --ignore-daemonsets --delete-local-data --force --timeout=120s"
                delete_command = f"kubectl --kubeconfig=/etc/kubernetes/admin.conf delete node {node_name_to_drain} --timeout=60s"

                commands_to_run = [drain_command, delete_command]
                command_names = ["Drain Node", "Delete Node"]

                for i, command_text in enumerate(commands_to_run):
                    logger.info(f"Executing SSM Command ({command_names[i]}): {command_text} on {control_plane_instance_id}")
                    response = ssm_client.send_command(
                        InstanceIds=[control_plane_instance_id],
                        DocumentName='AWS-RunShellScript',
                        Parameters={'commands': [command_text]},
                        TimeoutSeconds=180 # Increased timeout for drain
                    )
                    command_id = response['Command']['CommandId']
                    logger.info(f"SSM Command ID for {command_names[i]}: {command_id}")

                    # Wait for command completion
                    max_attempts = 60 # Try for up to 2 minutes
                    attempt = 0
                    command_succeeded = False
                    while attempt < max_attempts:
                        time.sleep(2) # Poll every 2 seconds
                        command_output = ssm_client.get_command_invocation(
                            CommandId=command_id,
                            InstanceId=control_plane_instance_id
                        )
                        status = command_output['Status']
                        logger.info(f"{command_names[i]} attempt {attempt+1}/{max_attempts} - Status: {status}")

                        if status == 'Success':
                            logger.info(f"{command_names[i]} successful. Output: {command_output.get('StandardOutputContent', '')}")
                            command_succeeded = True
                            break
                        elif status in ['Failed', 'Cancelled', 'TimedOut', 'Undeliverable', 'Terminated']:
                            error_content = command_output.get('StandardErrorContent', 'Unknown SSM error')
                            logger.error(f"{command_names[i]} via SSM failed. Status: {status}, Error: {error_content}")
                            # For drain, we might want to continue to delete node and complete lifecycle.
                            # For delete node, if it fails, we might still want to continue.
                            if command_names[i] == "Delete Node" and "NotFound" in error_content:
                                logger.warning(f"Node {node_name_to_drain} was already not found during delete. Assuming already deleted.")
                                command_succeeded = True # Treat as success if already gone
                            break # Break from polling loop on failure
                        attempt += 1

                    if not command_succeeded and command_names[i] == "Drain Node":
                        logger.warning(f"Drain command for {node_name_to_drain} did not complete successfully or timed out. Proceeding to delete node and complete lifecycle.")
                    elif not command_succeeded and command_names[i] == "Delete Node":
                        logger.warning(f"Delete node command for {node_name_to_drain} did not complete successfully. Proceeding to complete lifecycle action.")


                logger.info(f"Completing lifecycle action for instance {instance_id} with CONTINUE.")
                autoscaling.complete_lifecycle_action(
                    LifecycleHookName=lifecycle_hook_name,
                    AutoScalingGroupName=asg_name,
                    LifecycleActionResult='CONTINUE',
                    InstanceId=instance_id
                )
                return {'statusCode': 200, 'body': f"Node {node_name_to_drain} processed for termination."}

            except Exception as e:
            logger.error(f"Error processing scale-down event: {str(e)}")
            # Ensure lifecycle action is completed, even if with ABANDON
            if lifecycle_hook_name and asg_name and instance_id: # Check if these were defined
                logger.info(f"Completing lifecycle action for instance {instance_id} with ABANDON due to error.")
                autoscaling.complete_lifecycle_action(
                    LifecycleHookName=lifecycle_hook_name,
                    AutoScalingGroupName=asg_name,
                    LifecycleActionResult='ABANDON',
                    InstanceId=instance_id
                )
            return {'statusCode': 500, 'body': f"Error: {str(e)}"}
    else:
        logger.info(f"SNS message not a recognized lifecycle transition: {message.get('LifecycleTransition')}")
        # Fall through to token refresh if not a scale-down event or if SNS message structure is unexpected

# Default action: Refresh Kubeadm Join Token (if not an ASG termination event)
# This will run if the Lambda is triggered by CloudWatch Events (Scheduled)
# or if the SNS event was not 'autoscaling:EC2_INSTANCE_TERMINATING'.

# Check if this invocation is for token refresh (e.g. by checking event source or a specific field)
# For a simple scheduled event, 'source' will be 'aws.events'
is_scheduled_event = event.get('source') == 'aws.events'
is_sns_lifecycle_event = 'Records' in event and event['Records'][0].get('EventSource') == 'aws:sns' and \
                         message.get('LifecycleTransition') == 'autoscaling:EC2_INSTANCE_TERMINATING'

if not is_sns_lifecycle_event: # Proceed with token refresh if not a specific SNS lifecycle hook we handled
    logger.info("Running Kubeadm join command refresh logic...")
    try:
        ssm_command_to_run = 'kubeadm token create --print-join-command'
        logger.info(f"Sending SSM command to {control_plane_instance_id}: {ssm_command_to_run}")

        response = ssm_client.send_command(
            InstanceIds=[control_plane_instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': [ssm_command_to_run]},
            TimeoutSeconds=60
        )
        command_id = response['Command']['CommandId']
        logger.info(f"SSM Command ID for token refresh: {command_id}")

        max_attempts = 15 # Try for up to 30 seconds
        attempt = 0
        join_command = ""
        while attempt < max_attempts:
            time.sleep(2) # Poll every 2 seconds
            command_output = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=control_plane_instance_id
            )
            status = command_output['Status']
            logger.info(f"Token refresh attempt {attempt+1}/{max_attempts} - Status: {status}")
            if status == 'Success':
                join_command = command_output.get('StandardOutputContent', '').strip()
                if "kubeadm join" in join_command:
                    logger.info(f"Successfully generated new join command.")
                    break
                else:
                    logger.error(f"SSM command succeeded but output was not a valid join command: {join_command}")
                    join_command = "" # Invalidate if not a join command
                    # This might loop until max_attempts if output is weird but status is Success
            elif status in ['Failed', 'Cancelled', 'TimedOut', 'Undeliverable', 'Terminated']:
                error_content = command_output.get('StandardErrorContent', 'Unknown SSM error')
                logger.error(f"SSM command for token refresh failed. Status: {status}, Error: {error_content}")
                raise Exception(f"SSM command for token refresh failed: {error_content}")
            attempt += 1

        if not join_command:
            logger.error("SSM command for token refresh did not produce a join command within the attempts.")
            raise Exception("SSM command for token refresh did not complete successfully or yield a join command.")

        logger.info(f"Attempting to update secret: {join_command_latest_secret_id}")
        secrets_client.put_secret_value(
            SecretId=join_command_latest_secret_id, # Use the "latest" secret ID from env var
            SecretString=join_command
        )
        logger.info(f"Join command updated successfully in Secret: {join_command_latest_secret_id}")
        return {'statusCode': 200, 'body': 'Join command updated successfully'}

    except Exception as e:
        logger.error(f"Error during join command refresh: {str(e)}")
        return {'statusCode': 500, 'body': f"Error during join command refresh: {str(e)}"}
else:
    logger.info("SNS lifecycle hook processed, skipping token refresh logic for this invocation.")
    # This return is for the case where it was an SNS lifecycle hook that was handled above.
    # The return for that path is already done. This is just a final default if no path taken.
    return {'statusCode': 200, 'body': 'SNS lifecycle event processed.'}