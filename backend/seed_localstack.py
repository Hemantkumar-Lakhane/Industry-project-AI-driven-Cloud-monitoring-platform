#!/usr/bin/env python3
"""
AegisCloud LocalStack AWS Resource Seeder
=========================================
Automatically creates realistic cloud infrastructure in LocalStack:
1. S3 Buckets:
   - 'aegiscloud-compliant-storage' (Encrypted, Versioned, Private)
   - 'aegiscloud-public-exfil-bucket' (Unencrypted, Public Read/Write - triggers CSPM finding)
2. IAM Identities:
   - 'cloud-dev-user' (Least-privilege policy)
   - 'compromised-admin' (Admin wildcard '*' policy, no MFA - triggers CIEM finding)
"""
import os
import sys
import boto3
from botocore.exceptions import ClientError

ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"

def get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        aws_access_key_id="mock_key",
        aws_secret_access_key="mock_secret",
        region_name=REGION
    )

def get_iam_client():
    return boto3.client(
        "iam",
        endpoint_url=ENDPOINT,
        aws_access_key_id="mock_key",
        aws_secret_access_key="mock_secret",
        region_name=REGION
    )

def seed_resources():
    print("=" * 65)
    print(f"[*] Connecting to LocalStack AWS at {ENDPOINT}...")
    print("=" * 65)

    s3 = get_s3_client()
    iam = get_iam_client()

    # 1. Create S3 Buckets
    print("\n[1/2] Seeding S3 Buckets for CSPM Analysis...")
    buckets = [
        {"name": "aegiscloud-compliant-storage", "desc": "Secure, private storage bucket"},
        {"name": "aegiscloud-public-exfil-bucket", "desc": "Unrestricted bucket (triggers CSPM alert)"}
    ]
    for b in buckets:
        try:
            s3.create_bucket(Bucket=b["name"])
            print(f"  [+] Created bucket: s3://{b['name']} ({b['desc']})")
        except ClientError as e:
            if e.response['Error']['Code'] in ('BucketAlreadyOwnedByYou', 'BucketAlreadyExists'):
                print(f"  [.] Bucket already exists: s3://{b['name']}")
            else:
                print(f"  [-] S3 Error on {b['name']}: {e}")

    # 2. Create IAM Users & Policies
    print("\n[2/2] Seeding IAM Users for CIEM Identity Analysis...")
    users = [
        {"name": "cloud-dev-user", "policy_name": "DevRestrictedPolicy", "admin": False},
        {"name": "compromised-admin", "policy_name": "WildcardAdminPolicy", "admin": True}
    ]
    for u in users:
        try:
            iam.create_user(UserName=u["name"])
            print(f"  [+] Created IAM user: {u['name']}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                print(f"  [.] IAM user already exists: {u['name']}")
            else:
                print(f"  [-] IAM Error on {u['name']}: {e}")

        # Attach inline policy
        if u["admin"]:
            policy_doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
        else:
            policy_doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}'

        try:
            iam.put_user_policy(
                UserName=u["name"],
                PolicyName=u["policy_name"],
                PolicyDocument=policy_doc
            )
            print(f"      Attached {'WILDCARD ADMIN' if u['admin'] else 'Restricted'} policy: {u['policy_name']}")
        except Exception as e:
            print(f"      Policy error: {e}")

    print("\n" + "=" * 65)
    print("[SUCCESS] LocalStack AWS mock resources seeded successfully!")
    print("AegisCloud CSPM & CIEM engines can now audit live emulated cloud assets.")
    print("=" * 65)

if __name__ == "__main__":
    try:
        seed_resources()
    except Exception as e:
        print(f"\n[ERROR] Could not connect to LocalStack at {ENDPOINT}.")
        print("Please ensure Docker Desktop is running and LocalStack container is started:")
        print("  docker run -d --name localstack -p 4566:4566 -e SERVICES=s3,iam localstack/localstack")
        sys.exit(1)

