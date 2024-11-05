
import boto3
from botocore.config import Config
import json
import os
import time

def read_json(path: str, constants: dict) -> str:
    if not path.endswith('.json'):
        path = f'{path}.json'
    with open(path, 'r') as f:
        text = f.read()
    for key, value in constants.items():
        text = text.replace(f'{{{key}}}', value)
    return json.loads(text)

# [https://docs.aws.amazon.com/datasync/latest/userguide/tutorial_s3-s3-cross-account-transfer.html
def cp(id: str, src_profile: str, dst_profile: str,
          src_bucket: str, dst_bucket: str,
          src_path: str = '', dst_path: str = '',
          src_region: str = None, dst_region: str = None
       ):
    
    # Init
    print('Initializing')
    src_sesh = boto3.Session(profile_name = src_profile)
    dst_sesh = boto3.Session(profile_name = dst_profile)
    src_account = src_sesh.client('sts').get_caller_identity()['Account']
    print(f'- Src Account: {src_account}')
    src_region = src_sesh.client('s3').get_bucket_location(Bucket = src_bucket)['LocationConstraint']
    print(f'- Src Region: {src_region}')
    dst_region = dst_sesh.client('s3').get_bucket_location(Bucket = dst_bucket)['LocationConstraint']
    print(f'- Dst Region: {dst_region}')
    constants = {
        'DST_BUCKET': dst_bucket,
        'ID': id,
        'SRC_ACCOUNT': src_account,
        'SRC_BUCKET': src_bucket,
        'SRC_REGION': src_region,
    }

    # Step 1: In your source account, create a DataSync IAM role for destination bucket access
    # [https://docs.aws.amazon.com/datasync/latest/userguide/tutorial_s3-s3-cross-account-transfer.html#s3-s3-cross-account-create-iam-role-source-account]
    print('Step #1')
    iam = src_sesh.client('iam')

    dst_trust_policy = read_json('src_dst_role_trust', constants)
    dst_inline_policy = read_json('src_dst_role_permissions', constants)
    dst_role = f'{id}-dst'
    res = iam.create_role(
        RoleName = dst_role,
        AssumeRolePolicyDocument = json.dumps(dst_trust_policy),
        Description = 'DataSync role for source account',
    )
    dst_role_arn = res['Role']['Arn']
    print(f'- Dst Role: {dst_role_arn}')
    iam.attach_role_policy(
        RoleName = dst_role,
        PolicyArn = 'arn:aws:iam::aws:policy/AWSDataSyncFullAccess',
    )
    iam.attach_role_policy(
        RoleName = dst_role,
        PolicyArn = 'arn:aws:iam::aws:policy/AWSDataSyncReadOnlyAccess',
    )
    iam.put_role_policy(
        RoleName = dst_role,
        PolicyName = dst_role,
        PolicyDocument = json.dumps(dst_inline_policy),
    )

    src_trust_policy = read_json('src_src_role_trust', constants)
    src_inline_policy = read_json('src_src_role_permissions', constants)
    src_role = f'{id}-src'
    res = iam.create_role(
        RoleName = src_role,
        AssumeRolePolicyDocument = json.dumps(src_trust_policy),
        Description = 'DataSync role for source account',
    )
    src_role_arn = res['Role']['Arn']
    print(f'- Src Role: {src_role_arn}')
    iam.put_role_policy(
        RoleName = src_role,
        PolicyName = src_role,
        PolicyDocument = json.dumps(src_inline_policy),
    )
    
    # Step 2: In your destination account, update your S3 bucket policy
    # https://docs.aws.amazon.com/datasync/latest/userguide/tutorial_s3-s3-cross-account-transfer.html#s3-s3-cross-account-update-s3-policy-destination-account
    print('Step #2')
    dst_bucket_policy_new = read_json('dst_bucket_policy', constants)
    sid = dst_bucket_policy_new['Statement'][0]['Sid']
    s3 = dst_sesh.client('s3')
    old_bucket_policy = None
    try:
        old_bucket_policy = s3.get_bucket_policy(Bucket = dst_bucket)['Policy']
        with open('old_bucket_policy.json', 'w') as f:
            f.write(old_bucket_policy)
        dst_bucket_policy = json.loads(old_bucket_policy)
        if all([statement['Sid'] != sid for statement in dst_bucket_policy['Statement']]):
            dst_bucket_policy['Statement'].append(dst_bucket_policy_new['Statement'][0])
    except Exception:
        dst_bucket_policy = dst_bucket_policy_new
    while True:
        time.sleep(10)
        try:
            s3.put_bucket_policy(
                Bucket = dst_bucket,
                Policy = json.dumps(dst_bucket_policy),
            )
            break
        except Exception as e:
            print('*', e)
    print('- Dst Bucket Policy Updated')

    # Step 3: In your destination account, disable ACLs for your S3 bucket
    # https://docs.aws.amazon.com/datasync/latest/userguide/tutorial_s3-s3-cross-account-transfer.html#s3-s3-cross-account-disable-acls-destination-account
    print('Step #3')
    old_ownership_controls = s3.get_bucket_ownership_controls(Bucket = dst_bucket)['OwnershipControls']
    with open('old_ownership_controls.json', 'w') as f:
        json.dump(old_ownership_controls, f)
    s3.put_bucket_ownership_controls(
        Bucket = dst_bucket,
        OwnershipControls = {
            'Rules': [
                {
                    'ObjectOwnership': 'BucketOwnerEnforced',
                },
            ],
        },
    )

    # Step 4: In your source account, create your DataSync locations
    # https://docs.aws.amazon.com/datasync/latest/userguide/tutorial_s3-s3-cross-account-transfer.html#s3-s3-cross-account-create-locations
    print('Step #4')
    datasync_src = src_sesh.client('datasync', config = Config(region_name = src_region))
    src_location = datasync_src.create_location_s3(
        S3BucketArn = f'arn:aws:s3:::{src_bucket}',
        S3Config = {
            'BucketAccessRoleArn': f'arn:aws:iam::{src_account}:role/{src_role}',
        },
        S3StorageClass = 'STANDARD',
        Subdirectory = src_path,
    )
    src_loc_arn = src_location['LocationArn']
    print(f'- Src Location: {src_loc_arn}')
    datasync_dst = src_sesh.client('datasync', config = Config(region_name = dst_region))
    dst_location = datasync_dst.create_location_s3(
        S3BucketArn = f'arn:aws:s3:::{dst_bucket}',
        S3Config = {
            'BucketAccessRoleArn': f'arn:aws:iam::{src_account}:role/{dst_role}',
        },
        S3StorageClass = 'STANDARD',
        Subdirectory = dst_path,
    )
    dst_loc_arn = dst_location['LocationArn']
    print(f'- Dst Location: {dst_loc_arn}')
    
    # Step 5: In your source account, create and start your DataSync task
    # https://docs.aws.amazon.com/datasync/latest/userguide/tutorial_s3-s3-cross-account-transfer.html#s3-s3-cross-account-create-start-datasync-task
    print('Step #5')
    src_datasync_task = datasync_dst.create_task(
        SourceLocationArn = src_loc_arn,
        DestinationLocationArn = dst_loc_arn,
        Name = id,
        Options = {
            'LogLevel': 'BASIC',
            'ObjectTags': 'PRESERVE',
            'OverwriteMode': 'ALWAYS',
            'PreserveDeletedFiles': 'PRESERVE',
            'TaskQueueing': 'ENABLED',
            'TransferMode': 'ALL',
            'VerifyMode': 'ONLY_FILES_TRANSFERRED',
        },
        TaskMode = 'ENHANCED',
    )
    task_arn = src_datasync_task['TaskArn']
    print(f'- Task: {task_arn}')
    src_task_exec = datasync_dst.start_task_execution(TaskArn = task_arn)
    tast_exec_arn = src_task_exec['TaskExecutionArn']
    print(f'- Execution: {tast_exec_arn}')

    # Wait for completion
    print('Waiting')
    while True:
        time.sleep(10)
        try:
            src_task_exec = datasync_dst.describe_task_execution(
                TaskExecutionArn = tast_exec_arn,
            )
            status = src_task_exec['Status']
            print('-', status)
            if status == 'SUCCESS':
                with open('task_execution.json', 'w') as f:
                    json.dump(src_task_exec, f)
                break
        except Exception as e:
            print('*', e)
    
    # Cleanup
    print('Cleaning Up')
    datasync_dst.delete_task(TaskArn = task_arn)
    print('- Task deleted')
    datasync_dst.delete_location(LocationArn = dst_loc_arn)
    datasync_src.delete_location(LocationArn = src_loc_arn)
    print('- Locations deleted')
    s3.put_bucket_ownership_controls(Bucket = dst_bucket, OwnershipControls = old_ownership_controls)
    os.remove('old_ownership_controls.json')
    print('- Bucket Ownership Controls Restored')
    if old_bucket_policy is None:
        s3.delete_bucket_policy(Bucket = dst_bucket)
    else:
        s3.put_bucket_policy(Bucket = dst_bucket, Policy = old_bucket_policy)
        os.remove('old_bucket_policy.json')
    print('- Bucket Policy Restored')
    iam.detach_role_policy(RoleName = dst_role, PolicyArn = 'arn:aws:iam::aws:policy/AWSDataSyncFullAccess')
    iam.detach_role_policy(RoleName = dst_role, PolicyArn = 'arn:aws:iam::aws:policy/AWSDataSyncReadOnlyAccess')
    iam.delete_role_policy(RoleName = dst_role, PolicyName = dst_role)
    iam.delete_role(RoleName = dst_role)
    iam.delete_role_policy(RoleName = src_role, PolicyName = src_role)
    iam.delete_role(RoleName = src_role)
    print('- Roles deleted')
    print('Done')

cp('ds3', 'embryonics', 'rhea', 'transfer-data-from-labs', 'rhea-test', src_path = 'chicago', dst_path = 'chicago')
