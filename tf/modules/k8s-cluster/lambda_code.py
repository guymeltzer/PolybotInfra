import boto3
import json
import time
import re
import random
import string
from datetime import datetime

def lambda_handler(event, context):
    autoscaling = boto3.client('autoscaling')
    ssm_client = boto3.client('ssm')
    secrets_client = boto3.client('secretsmanager')
    region = '${var.region}'
    control_plane_instance_id = '${aws_instance.control_plane.id}'
    
    print(f"Event received: {json.dumps(event)}")
    
    if 'Records' in event and event['Records'][0]['EventSource'] == 'aws:sns':
        print("SNS event detected")
        message = json.loads(event['Records'][0]['Sns']['Message'])
        print(f"SNS message: {message}")
        if message.get('LifecycleTransition') == 'autoscaling:EC2_INSTANCE_TERMINATING':
            print("Processing scale-down event")
            instance_id = message['EC2InstanceId']
            lifecycle_hook_name = message['LifecycleHookName']
            asg_name = message['AutoScalingGroupName']
            
            try:
                ec2_client = boto3.client('ec2', region_name=region)
                response = ec2_client.describe_instances(InstanceIds=[instance_id])
                tags = response['Reservations'][0]['Instances'][0]['Tags']
                private_ip = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
                node_name = next((tag['Value'] for tag in tags if tag['Key'] == 'Name'), f"node/{private_ip}")
                print(f"Draining node: {node_name}")
                
                # Drain and delete the node
                drain_command = f"kubectl --kubeconfig=/etc/kubernetes/admin.conf drain --ignore-daemonsets --delete-emptydir-data --force {node_name}"
                delete_command = f"kubectl --kubeconfig=/etc/kubernetes/admin.conf delete node {node_name}"
                
                # Execute drain command
                response = ssm_client.send_command(
                    InstanceIds=[control_plane_instance_id],
                    DocumentName='AWS-RunShellScript',
                    Parameters={'commands': [drain_command]},
                    TimeoutSeconds=300
                )
                
                command_id = response['Command']['CommandId']
                max_attempts = 60
                attempt = 0
                while attempt < max_attempts:
                    time.sleep(2)
                    command_output = ssm_client.get_command_invocation(
                        CommandId=command_id,
                        InstanceId=control_plane_instance_id
                    )
                    if command_output['Status'] in ['Success', 'Completed']:
                        print("Node drained successfully")
                        break
                    elif command_output['Status'] in ['Failed', 'Cancelled', 'TimedOut']:
                        raise Exception(f"Drain failed: {command_output.get('StandardErrorContent', 'Unknown error')}")
                    attempt += 1
                else:
                    print("Drain command still running; proceeding with termination")
                
                # Execute delete command
                response = ssm_client.send_command(
                    InstanceIds=[control_plane_instance_id],
                    DocumentName='AWS-RunShellScript',
                    Parameters={'commands': [delete_command]},
                    TimeoutSeconds=300
                )
                
                command_id = response['Command']['CommandId']
                max_attempts = 60
                attempt = 0
                while attempt < max_attempts:
                    time.sleep(2)
                    command_output = ssm_client.get_command_invocation(
                        CommandId=command_id,
                        InstanceId=control_plane_instance_id
                    )
                    if command_output['Status'] in ['Success', 'Completed']:
                        print("Node deleted successfully")
                        break
                    elif command_output['Status'] in ['Failed', 'Cancelled', 'TimedOut']:
                        raise Exception(f"Delete failed: {command_output.get('StandardErrorContent', 'Unknown error')}")
                    attempt += 1
                else:
                    print("Delete command still running; proceeding with termination")
                
                autoscaling.complete_lifecycle_action(
                    LifecycleHookName=lifecycle_hook_name,
                    AutoScalingGroupName=asg_name,
                    LifecycleActionResult='CONTINUE',
                    InstanceId=instance_id
                )
                return {'statusCode': 200, 'body': 'Node drained, deleted, and termination completed'}
            except Exception as e:
                print(f"Error: {str(e)}")
                autoscaling.complete_lifecycle_action(
                    LifecycleHookName=lifecycle_hook_name,
                    AutoScalingGroupName=asg_name,
                    LifecycleActionResult='ABANDON',
                    InstanceId=instance_id
                )
                return {'statusCode': 500, 'body': f"Error: {str(e)}"}
    
    print("Running join command refresh logic")
    try:
        # First check if the control plane is ready
        check_command = "kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes"
        response = ssm_client.send_command(
            InstanceIds=[control_plane_instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': [check_command]},
            TimeoutSeconds=60
        )
        
        command_id = response['Command']['CommandId']
        attempt = 0
        max_attempts = 15
        while attempt < max_attempts:
            time.sleep(5)
            try:
                command_output = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=control_plane_instance_id
                )
                if command_output['Status'] in ['Success', 'Completed']:
                    print("Kubernetes control plane verified as running")
                    print(f"Nodes: {command_output.get('StandardOutputContent', 'No output')}")
                    break
                elif command_output['Status'] in ['Failed', 'Cancelled', 'TimedOut']:
                    print(f"Control plane check failed: {command_output.get('StandardErrorContent', 'Unknown error')}")
                    if attempt >= max_attempts - 1:
                        return {'statusCode': 500, 'body': 'Control plane not ready'}
                    # If failed, wait and try again
                    time.sleep(5)
            except Exception as e:
                print(f"Error checking command status: {str(e)}")
                time.sleep(5)
            
            attempt += 1
        
        # Create a fresh token on the control plane
        token_command = 'kubeadm token create --print-join-command'
        print(f"Sending command to create token: {token_command}")
        
        response = ssm_client.send_command(
            InstanceIds=[control_plane_instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': [token_command]},
            TimeoutSeconds=120
        )
        
        command_id = response['Command']['CommandId']
        max_attempts = 20
        attempt = 0
        while attempt < max_attempts:
            time.sleep(5)
            try:
                command_output = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=control_plane_instance_id
                )
                if command_output['Status'] in ['Success', 'Completed']:
                    join_command = command_output['StandardOutputContent'].strip()
                    print(f"Join command updated: {join_command}")
                    break
                elif command_output['Status'] in ['Failed', 'Cancelled', 'TimedOut']:
                    error = command_output.get('StandardErrorContent', 'Unknown error')
                    raise Exception(f"SSM command failed: {error}")
                # Still running, wait longer
                time.sleep(5)
            except Exception as e:
                print(f"Error checking token command: {str(e)}")
                time.sleep(5)
            attempt += 1
        else:
            raise Exception("SSM command did not complete within reasonable time")
        
        # Create a timestamp for the new secret
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        secret_name = '${aws_secretsmanager_secret.kubernetes_join_command.name}'
        
        # Store the join command in the secret
        try:
            # First try to update the existing secret
            print(f"Updating secret: {secret_name}")
            secrets_client.put_secret_value(
                SecretId=secret_name,
                SecretString=join_command
            )
            print(f"Secret {secret_name} updated successfully")
        except Exception as e:
            # If that fails, try creating a new secret value
            print(f"Error updating secret: {str(e)}")
            try:
                # Try a direct put-secret-value as fallback
                secrets_client.put_secret_value(
                    SecretId=secret_name,
                    SecretString=join_command
                )
                print(f"Secret updated via fallback method")
            except Exception as inner_e:
                print(f"Both secret update methods failed: {str(inner_e)}")
                return {'statusCode': 500, 'body': f"Failed to update secret: {str(inner_e)}"}
        
        return {'statusCode': 200, 'body': 'Join command updated successfully'}
    except Exception as e:
        print(f"Error in token refresh: {str(e)}")
        return {'statusCode': 500, 'body': f"Error: {str(e)}"}
