import os
import requests
import yaml
import boto3
from botocore.exceptions import ClientError
from git import Repo, GitCommandError


class Ec2Metadata:
    """Handles communication with EC2 Instance Metadata."""

    BASE_URL = "http://169.254.169.254/latest"

    def __init__(self):
        self.token = self._get_token()

    def _get_token(self):
        """Fetches the session token."""
        url = f"{self.BASE_URL}/api/token"
        headers = {"X-aws-ec2-metadata-token-ttl-seconds": "600"}
        response = requests.put(url, headers=headers, timeout=2)
        response.raise_for_status()
        return response.text

    def get_value(self, path):
        """Retrieves specific metadata based on the provided path."""
        url = f"{self.BASE_URL}/{path}"
        headers = {"X-aws-ec2-metadata-token": self.token}
        response = requests.get(url, headers=headers, timeout=2)
        response.raise_for_status()
        return response.text

class EC2SgManager:
    """Handles replacement of Security Group rules."""

    def __init__(self):
        self.metadata = Ec2Metadata()
        self.region = self.metadata.get_value("meta-data/placement/region")
        self.instance_id = self.metadata.get_value("meta-data/instance-id")
        self.ec2 = boto3.client('ec2', region_name=self.region)

    def get_primary_sg_id(self):
        response = self.ec2.describe_instances(InstanceIds=[self.instance_id])
        return response['Reservations'][0]['Instances'][0]['SecurityGroups'][0]['GroupId']

    def replace_port_rules(self, sg_id, port, new_cidr_list):
        """
        Finds all existing rules for a specific port, removes them,
        and adds the new CIDR ranges provided.
        """
        try:
            # Fetch current rules
            sg_details = self.ec2.describe_security_groups(GroupIds=[sg_id])
            existing_permissions = sg_details['SecurityGroups'][0].get('IpPermissions', [])

            # Filter rules that match the target port
            rules_to_revoke = [
                rule for rule in existing_permissions
                if rule.get('FromPort') == port or rule.get('ToPort') == port
            ]

            # Revoke matching rules
            if rules_to_revoke:
                print(f"Removing {len(rules_to_revoke)} existing rule(s) for Port {port}...")
                self.ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=rules_to_revoke)
            else:
                print(f"No existing rules found for Port {port}.")

            # Authorize new rules
            new_ip_permissions = [{
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [{'CidrIp': cidr, 'Description': 'Updated via Script'} for cidr in new_cidr_list]
            }]

            print(f"Adding new access for Port {port} from: {', '.join(new_cidr_list)}")
            self.ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=new_ip_permissions)
            print(f"Successfully updated Port {port} rules.")

        except ClientError as e:
            print(f"Error: {e}")

class ConfigManager:
    """Handles input configuration."""

    def __init__(self, yaml_path, cloudflare_url, static_ips):
        self.yaml_path = yaml_path
        self.cloudflare_url = cloudflare_url
        self.static_ips = static_ips

    def fetch_cloudflare_ipv4(self):
        response = requests.get(self.cloudflare_url, timeout=10)
        response.raise_for_status()
        return response.text.strip().splitlines()

    def load_yaml(self):
        with open(self.yaml_path, "r") as f:
            return yaml.safe_load(f)

    def save_yaml(self, data):
        with open(self.yaml_path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False)

    def update_http_rules(self):
        cloudflare_ips = self.fetch_cloudflare_ipv4()
        unique_sorted_ips = sorted(set(cloudflare_ips + self.static_ips))

        data = self.load_yaml()
        data.setdefault("rules", {})
        data["rules"]["http"] = unique_sorted_ips

        self.save_yaml(data)
        return unique_sorted_ips

class GitManager:
    """Handles Git operations: add, commit, and push."""

    def __init__(self, repo_path, remote_name='origin', branch='main'):
        self.repo_path = repo_path
        self.remote_name = remote_name
        self.branch = branch
        try:
            self.repo = Repo(repo_path)
        except Exception as e:
            print(f"Error initializing repo at {repo_path}: {e}")
            self.repo = None

    def push_updates(self, file_list, commit_message):
        """Stages files, commits them, and pushes to remote."""
        if not self.repo:
            return

        try:
            # Add
            self.repo.index.add(file_list)

            # Commit
            if self.repo.is_dirty(untracked_files=True):
                self.repo.index.commit(commit_message)
                print(f"Committed: {commit_message}")

                # Push
                origin = self.repo.remote(name=self.remote_name)
                origin.push(self.branch)
                print(f"Successfully pushed to {self.remote_name}/{self.branch}")
            else:
                print("No changes detected. Nothing to push.")

        except GitCommandError as e:
            print(f"Git error: {e}")


if __name__ == "__main__":
    my_static_ip = ["178.74.238.169/32"]
    cloudflare_ipv4 = "https://www.cloudflare.com/ips-v4"
    yaml_file = "sec-group.yaml"

    # Generate and save new SG configuration
    configuration = ConfigManager(
        yaml_path=yaml_file,
        cloudflare_url=cloudflare_ipv4,
        static_ips=my_static_ip,
    )

    new_allowed_ips = configuration.update_http_rules()
    print(new_allowed_ips)

    # Update instance security group
    manager = EC2SgManager()
    target_sg = manager.get_primary_sg_id()
    manager.replace_port_rules(target_sg, port=80, new_cidr_list=new_allowed_ips)

    # Push to git
    current_directory = os.path.dirname(os.path.abspath(__file__))
    git_gate = GitManager(repo_path=current_directory)
    git_gate.push_updates(
        file_list=[yaml_file],
        commit_message="chore(http): updated Ingress IPs"
    )
