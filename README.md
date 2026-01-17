# EC2 Security Group Automator 🛡️

A Python-based tool designed to run directly on an EC2 instance to manage Security Group rules and synchronize code changes with GitHub.

## Overview
This script performs a **targeted replacement** of ingress rules for **Port 80**. It dynamically detects the instance's environment, identifies the primary Security Group, revokes all current Port 80 rules, and applies a fresh set of CIDR ranges.

## Features
- **Dynamic Region & ID Detection**: Uses **IMDSv2** (Instance Metadata Service) to identify the local AWS environment without hardcoded strings.
- **Atomic Port Reset**: Specifically wipes and replaces Port 80 rules while leaving other ports (like SSH 22) untouched.
- **OOP Architecture**: Modular design separating Metadata fetching, EC2 management, and Git operations.
- **Git Auto-Sync**: Automatically stages, commits, and pushes the configuration to your repository after execution.

## Setup Instructions

### 1. AWS IAM Requirements
The EC2 instance must be attached to an **IAM Instance Profile** with the following policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "*"
        }
    ]
}
```

### 2. Dependencies
Install the required Python libraries on your instance:

```shell
pip3 install boto3 requests GitPython botocore PyYAML
```

### 3. Git Configuration
Ensure Git is configured with your identity to allow the script to commit(ssh key example):

```shell
git config --global user.name "Your Name"
git config --global user.email "your-email@example.com"
eval `ssh-agent`
ssh-add id_rsa
```

## Usage
Update the **ALLOWED_IP** list in the script with your desired CIDR blocks.
Run the script:

```shell
python3 script.py
```
