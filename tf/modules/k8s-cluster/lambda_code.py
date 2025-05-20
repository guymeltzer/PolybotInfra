import boto3
import json
import time
import re

def lambda_handler(event, context):
    autoscaling = boto3.client('autoscaling')
    ssm_client = boto3.client('ssm')
    secrets_client = boto3.client('secretsmanager')
    region = 'us-east-1'
    control_plane_instance_id = 'i-0766ed787297ada3d'
    
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
        response = ssm_client.send_command(
            InstanceIds=[control_plane_instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': ['kubeadm token create --print-join-command']}
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
        
        # Create a new secret with timestamp
        timestamp = time.strftime("%Y%m%d%H%M%S")
        new_secret_name = f"kubernetes-join-command-{timestamp}"
        
        # Create the new secret
        try:
            secrets_client.create_secret(
                Name=new_secret_name,
                Description='Kubernetes join command for worker nodes',
                SecretString=join_command
            )
            print(f"Created new secret: {new_secret_name}")
            
            # List existing join command secrets to clean up old ones
            response = secrets_client.list_secrets(
                Filters=[{'Key': 'name', 'Values': ['kubernetes-join-command-*']}]
            )
            
            # Sort secrets by creation date, newest first
            if 'SecretList' in response:
                secrets = sorted(response['SecretList'], 
                                key=lambda x: x.get('CreatedDate', ''), 
                                reverse=True)
                
                # Keep the newest 2 secrets, delete the rest
                for secret in secrets[2:]:
                    name = secret.get('Name', '')
                    if re.match(r'kubernetes-join-command-\d+', name):
                        try:
                            print(f"Deleting old secret: {name}")
                            secrets_client.delete_secret(
                                SecretId=name,
                                ForceDeleteWithoutRecovery=True
                            )
                        except Exception as del_err:
                            print(f"Failed to delete secret {name}: {str(del_err)}")
        except Exception as sec_err:
            print(f"Error creating/managing secrets: {str(sec_err)}")
            raise
            
        return {'statusCode': 200, 'body': 'Join command updated successfully'}
    except Exception as e:
        print(f"Error: {str(e)}")
        return {'statusCode': 500, 'body': f"Error: {str(e)}"}
