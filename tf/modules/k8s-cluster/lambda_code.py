import boto3
import json
import time
import re
import random
import string

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
            TimeoutSeconds=30
        )
        
        command_id = response['Command']['CommandId']
        attempt = 0
        max_attempts = 10
        while attempt < max_attempts:
            time.sleep(2)
            try:
                command_output = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=control_plane_instance_id
                )
                if command_output['Status'] in ['Success', 'Completed']:
                    print("Kubernetes control plane verified as running")
                    break
                elif command_output['Status'] in ['Failed', 'Cancelled', 'TimedOut']:
                    print(f"Control plane check failed: {command_output.get('StandardErrorContent', 'Unknown error')}")
                    return {'statusCode': 500, 'body': 'Control plane not ready'}
            except Exception as e:
                print(f"Error checking command status: {str(e)}")
                attempt += 1
                continue
            
            attempt += 1
        
        # Create a fresh token on the control plane
        response = ssm_client.send_command(
            InstanceIds=[control_plane_instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': ['kubeadm token create --print-join-command']},
            TimeoutSeconds=60
        )
        
        command_id = response['Command']['CommandId']
        max_attempts = 15
        attempt = 0
        while attempt < max_attempts:
            time.sleep(2)
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
            attempt += 1
        else:
            raise Exception("SSM command did not complete within 30 seconds")
        
        # Update the latest secret with the new join command
        try:
            latest_secret = secrets_client.list_secrets(
                Filters=[{'Key': 'name', 'Values': ['kubernetes-join-command-*']}],
                SortOrder='desc'
            )['SecretList'][0]['Name']
            
            print(f"Updating secret: {latest_secret}")
            
            secrets_client.put_secret_value(
                SecretId=latest_secret,
                SecretString=join_command
            )
        except Exception as e:
            print(f"Error updating latest secret, creating new value directly: {str(e)}")
            # If we fail to find or update the latest secret, try a direct approach
            try:
                secrets_client.update_secret(
                    SecretId="kubernetes-join-command-*",
                    SecretString=join_command
                )
            except Exception as inner_e:
                print(f"Direct secret update failed too: {str(inner_e)}")
                
        return {'statusCode': 200, 'body': 'Join command updated successfully'}
    except Exception as e:
        print(f"Error: {str(e)}")
        return {'statusCode': 500, 'body': f"Error: {str(e)}"}
