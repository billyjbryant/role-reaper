import argparse
import json
import time
import boto3
import botocore.exceptions as botoexceptions
import pandas as pd
import logging
import os
import threading
from tqdm import tqdm
import structlog
import re

backup = False
dry_run = False
tag_key = "RoleReaper"
backup_folder = "./backup-templates"
logger = structlog.getLogger(f"{tag_key}:Disabler")


def boto3_log_level(log_level: int):
    """
    Set the log level for the boto3 library

    Args:
        log_level (int): The log level to set the boto3 library to
    """
    logging.getLogger("botocore").setLevel(log_level)
    logging.getLogger("boto3").setLevel(log_level)
    logging.getLogger("botocore.auth").setLevel(log_level)
    logging.getLogger("botocore.endpoint").setLevel(log_level)
    logging.getLogger("botocore.parsers").setLevel(log_level)
    logging.getLogger("botocore.retryhandler").setLevel(log_level)
    logging.getLogger("botocore.hooks").setLevel(log_level)
    logging.getLogger("botocore.credentials").setLevel(log_level)
    logging.getLogger("botocore.client").setLevel(log_level)


def set_log_level(log_level: str = "info"):
    """
    Set the log level for the logger

    Args:
        log_level (string): The log level to set the logger to (DEBUG, INFO, WARNING, ERROR, CRITICAL) Default: INFO
    """
    log_level_mapping = {
        r"debug": "DEBUG",
        r"info": "INFO",
        r"warn(ing)?": "WARNING",
        r"err(or)?": "ERROR",
        r"crit(ical)?": "CRITICAL",
    }
    matched_level = next(
        (
            full
            for pattern, full in log_level_mapping.items()
            if re.match(pattern, log_level)
        ),
        None,
    )
    LOG_LEVEL = getattr(logging, matched_level) if matched_level else logging.INFO
    boto3_log_level(LOG_LEVEL)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(LOG_LEVEL))
    logger.info(f"Log level set to {matched_level}")

def parse_arguments():
    """
    Parse the command line arguments

    Returns:
        Object: The parsed arguments
    """
    parser = argparse.ArgumentParser(description="Enable or Disable AWS IAM Roles.")
    parser.add_argument(
        "file_path",
        type=str,
        help="Path to the file containing role names (txt, csv, json).",
    )
    parser.add_argument(
        "--backup-folder",
        type=str,
        help="Folder to save CloudFormation templates of roles before disabling.",
        default="./backup-templates"
    )
    parser.add_argument(
        "--backup", action="store_true", help="Backup the roles before disabling."
    )
    parser.add_argument(
        "--enable", action="store_true", help="Enable the specified roles."
    )
    parser.add_argument(
        "--disable", action="store_true", help="Disable the specified roles."
    )
    parser.add_argument(
        "--delete", action="store_true", help="Delete the specified roles."
    )
    parser.add_argument(
        "--restore", action="store_true", help="Restore the specified roles from backup."
    )
    parser.add_argument(
        "-d", "--dry-run", action="store_true", help="Print actions without executing."
    )
    parser.add_argument(
        "-k", "--tag-key", type=str, help="Tag key to use for tracking disabled roles."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging."
    )
    parser.set_defaults(backup=False, dry_run=False, tag_key="RoleReaper", verbose=os.environ.get("DEBUG", False))
    return parser.parse_args()


def read_roles(file_path):
    """
    Read the file containing role names and return them in a list

    Args:
        file_path (string): The path to the file containing role names

    Returns:
        List: The list of role names
    """
    try:
        if file_path.endswith(".json"):
            with open(file_path, "r") as file:
                return json.load(file)
        elif file_path.endswith(".csv"):
            return pd.read_csv(file_path)["RoleName"].tolist()
        elif file_path.endswith(".txt"):
            with open(file_path, "r") as file:
                return [line.strip() for line in file if line.strip()]
        else:
            raise ValueError("Unsupported file format. Please use txt, csv, or json.")
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise (f"Error reading file {file_path}: {e}")


def make_api_call(client, method, **kwargs):
    """
    Make an AWS API call with exponential backoff

    Args:
        client (Object): The client object to make the API call
        method (string): The method to call on the client object
        **kwargs: The arguments to pass to the method
    
    Returns:
        Object: The response from the API call
    """
    attempts = 0
    max_attempts = 5
    delay = 1  # Start with 1 second

    logger.debug(f"Making API call: {client}.{method}({kwargs})")
    while attempts < max_attempts:
        try:
            response = getattr(client, method)(**kwargs)
            logger.debug(f"API call successful: {method}({kwargs}): {response}")
            return response
        except botoexceptions.ClientError as e:
            if e.response["Error"]["Code"] == "Throttling":
                time.sleep(delay)
                delay *= 2  # Exponential backoff
                attempts += 1
            else:
                raise
        except botoexceptions.BotoCoreError:
            time.sleep(delay)
            delay *= 2
            attempts += 1
    raise Exception(f"API call failed after {max_attempts} attempts.")


def get_role(client, role_name):
    """
    Get the details of an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to get

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Getting role: {role_name}")
    try:
        response = make_api_call(client, "get_role", RoleName=role_name)
        role = response.get("Role", {})
        logger.debug(f"Role {role_name} found: {role}")
        return role
    except Exception as e:
        logger.error(f"Error getting role {role_name}: {e}")
        return None

def get_role_tags(client, role_name):
    """
    Get the tags of an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to get tags for

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Getting tags for role: {role_name}")
    try:
        response = make_api_call(client, "list_role_tags", RoleName=role_name)
        tags = response.get("Tags", [])
        logger.debug(f"Tags for role {role_name}: {tags}")
        return tags
    except Exception as e:
        logger.error(f"Error getting tags for role {role_name}: {e}")
        return None


def get_role_policies(client, role_name):
    """
    Get the policies attached to an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to get policies for

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Getting policies for role: {role_name}")
    try:
        response = make_api_call(
            client, "list_attached_role_policies", RoleName=role_name
        )
        policies = response.get("AttachedPolicies", [])
        logger.debug(f"Policies for role {role_name}: {policies}")
        return policies
    except Exception as e:
        logger.error(f"Error getting policies for role {role_name}: {e}")
        return None


def get_inline_policies(client, role_name):
    """
    Get the inline policies attached to an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to get inline policies for

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Getting inline policies for role: {role_name}")
    try:
        response = make_api_call(client, "list_role_policies", RoleName=role_name)
        policies = response.get("PolicyNames", [])
        logger.debug(f"Inline policies for role {role_name}: {policies}")
        return policies
    except Exception as e:
        logger.error(f"Error getting inline policies for role {role_name}: {e}")
        return None


def get_role_policy(client, role_name, policy_name):
    """
    Get the policy attached to an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to get the policy for
        policy_name (string): The name of the policy to get

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Getting policy {policy_name} for role: {role_name}")
    try:
        response = make_api_call(client, "get_role_policy", RoleName=role_name, PolicyName=policy_name)
        policy_document = response.get("PolicyDocument", "")
        logger.debug(f"Policy {policy_name} for role {role_name}: {policy_document}")
        return policy_document
    except Exception as e:
        logger.error(f"Error getting policy {policy_name} for role {role_name}: {e}")
        return None


def get_role_details(client, role_name):
    """
    Get all details of a role including inline policies (and their content), managed policies (name) and tags

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to get details for

    Returns:
        Object: The details and tags of the IAM role
    """
    logger.debug(f"Getting details for role: {role_name}")
    try:
        role = {}
        role_detail = get_role(client, role_name)
        if not role_detail:
            return None
        role["RoleDetail"] = get_role(client, role_name)
        role["Tags"] = role["RoleDetail"]["Tags"] if role["RoleDetail"]["Tags"] else get_role_tags(client, role_name)
        role["AttachedPolicies"] = get_role_policies(client, role_name)

        inline_policies = []
        policies = get_inline_policies(client, role_name)
        for policy_name in policies:
            if policy_name == "RoleReaperDisablePolicy":
                continue
            policy_document = get_role_policy(client, role_name, policy_name)
            inline_policies.append({'PolicyName': policy_name, 'PolicyDocument': policy_document})

        role["InlinePolicies"] = inline_policies
        logger.debug(f"Details for role {role_name}: {role}")
        return role
    except Exception as e:
        logger.error(f"Error getting details for role {role_name}: {e}")
        return None


def create_cloudformation_template(client, role_name):
    """
    Create a CloudFormation template for the role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to create the template for

    Returns:
        string: The CloudFormation template
    """
    logger.debug(f"Creating CloudFormation template for role: {role_name}")
    try:
        role = get_role_details(client, role_name)

        if not role:
            logger.error(f"Role {role_name} not found")
            return None

        resources = {}
        tags = []
        for tag in role["Tags"]:
            if tag_key in tag["Key"]:
                continue
            tags.append(tag)

        role_resources = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role["RoleDetail"]["RoleName"],
                "AssumeRolePolicyDocument": role["RoleDetail"]["AssumeRolePolicyDocument"],
                "Tags": tags,
            },
        }

        if role["RoleDetail"].get("Description", None):
            role_resources["Properties"]["Description"] = role["RoleDetail"].get(
                "Description", None
            )

        if role["RoleDetail"]["Path"] != "/" and role["RoleDetail"]["Path"] != "/service-role/":
            role_resources["Properties"]["Path"] = role["RoleDetail"]["Path"]

        if role["InlinePolicies"]:
            role_resources["Properties"]["Policies"] = [
                {
                    "PolicyName": policy["PolicyName"],
                    "PolicyDocument": policy["PolicyDocument"],
                } for policy in role["InlinePolicies"]
            ]

        if role["AttachedPolicies"]:
            role_resources["Properties"]["ManagedPolicyArns"] = [policy["PolicyArn"] for policy in role["AttachedPolicies"]]

        resource_name = role_name.replace(" ", "").replace("/", "").replace("-", "")
        resources[resource_name] = role_resources
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": resources,
        }

        logger.debug(f"CloudFormation template for role {role_name}: {template}")
        logger.info(f"CloudFormation template for role {role_name} created")
        try:
            final_template = json.dumps(template, indent=2)
            logger.debug(f"CloudFormation template: {final_template}")
            return final_template
        except Exception as e:
            logger.error(f"Error converting Template to String for {role_name}: {e}")
            raise
    except Exception as e:
        logger.error(f"Error creating CloudFormation template for role {role_name}: {e}")
        raise


def save_cloudformation_template(client, role_name, template, file_path):
    """
    Save the CloudFormation template for the role to a file

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to create the template for
        file_path (string): The path to save the template to
    """
    logger.debug(f"Saving CloudFormation template for role: {role_name}")
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, "w") as file:
            file.write(template)
        logger.info(f"CloudFormation template for role {role_name} saved to {file_path}")
        return
    except Exception as e:
        logger.error(f"Error saving CloudFormation template for role {role_name}: {e}")
        raise


def backup_role(client, role_name, backup_folder):
    """
    Backup the role to a CloudFormation template

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to backup
        backup_folder (string): The folder to save the backup to
    """
    sanitized_role_name = re.sub(
        r"[^a-zA-Z0-9-_]", "", role_name.replace(" ", "_").replace("/", "-")
    )
    logger.debug(f"Backing up role: {role_name}")
    try:
        try:
            template = create_cloudformation_template(client, role_name)
        except Exception as e:
            logger.error(f"Error creating template for role {role_name}: {e}")
            raise
        if not template:
            logger.warning(f"No template created for role {role_name}")
            return
        file_name = (
            f"{sanitized_role_name}-{time.strftime('%Y%m%d-%H%M%S')}.template.json"
        )
        save_cloudformation_template(client, role_name, template, f"{backup_folder}/{file_name}")
        return template
    except Exception as e:
        logger.error(f"Error backing up role {role_name}: {e}")
        raise


def tag_role(client, role_name, key, value):
    """Tag an IAM role with a key and value

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to tag
        key (string): The tag key
        value (string): The tag value
    
    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Tagging role {role_name} with key: {key} and value: {value}")
    if not dry_run:
        try:
            tags = get_role_tags(client, role_name)
            if key in [tag["Key"] for tag in tags]:
                logger.warning(f"Role {role_name} already tagged with key: {key}")
                return
            response = make_api_call(
                client,
                "tag_role",
                RoleName=role_name,
                Tags=[{"Key": key, "Value": value}],
            )
            logger.info(f"Role {role_name} tagged with key: {key} and value: {value}")
            return response
        except Exception as e:
            logger.error(f"Error tagging role {role_name}: {e}")


def untag_role(client, role_name, key):
    """Untag an IAM role with a key

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to untag
        key (string): The tag key to remove

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Untagging role {role_name} with key: {key}")
    if not dry_run:
        try:
            tags = get_role_tags(client, role_name)
            if not key in [tag["Key"] for tag in tags]:
                logger.warning(f"Role {role_name} not tagged with key: {key}")
                return
            response = make_api_call(client, "untag_role", RoleName=role_name, TagKeys=[key])
            logger.info(f"Role {role_name} untagged with key: {key}")
            return response
        except Exception as e:
            logger.error(f"Error untagging role {role_name}: {e}")


def disable_role(client, role_name):
    """Disable an IAM role

    Args:
        client (Object): The IAM client object

    Returns:
        Object: The response from the API call
    """
    disable_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RoleReaperDisableRole",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    logger.debug(f"Disabling role: {role_name}")
    if not dry_run:
        try:
            if not get_role(client, role_name):
                logger.warning(f"Role {role_name} not found")
                return
            tags = get_role_tags(client, role_name)
            logger.debug(f"[disable_role] Tags for role {role_name}: {tags}")
            if tags:
                tag_keys = [tag["Key"] for tag in tags]
                logger.debug(f"[disable_role] Tag keys for role {role_name}: {tag_keys}")
                if f"{tag_key}:Disabled" in tag_keys:
                    logger.warning(f"Role {role_name} already disabled")
                    return
            response = make_api_call(
                client,
                "put_role_policy",
                RoleName=role_name,
                PolicyName="RoleReaperDisablePolicy",
                PolicyDocument=json.dumps(disable_role_policy),
            )
            tag_role(client, role_name, f"{tag_key}:Disabled", "true")
            tag_role(client, role_name, tag_key, "true")
            logger.info(f"Role {role_name} disabled")
            return response
        except Exception as e:
            logger.error(f"Error disabling role {role_name}: {e}")
            raise


def enable_role(client, role_name):
    """
    Enable an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to enable

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Enabling role: {role_name}")
    if not dry_run:
        try:
            tags = get_role_tags(client, role_name)
            if not f"{tag_key}:Disabled" in [tag["Key"] for tag in tags]:
                logger.warning(f"Role {role_name} is not disabled")
                return
            response = make_api_call(
                client,
                "delete_role_policy",
                RoleName=role_name,
                PolicyName="RoleReaperDisablePolicy",
            )
            untag_role(client, role_name, f"{tag_key}:Disabled")
            logger.info(f"Role {role_name} enabled")
            return response
        except Exception as e:
            logger.error(f"Error enabling role {role_name}: {e}")


def delete_role(client, role_name):
    """
    Delete an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to delete

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Deleting role: {role_name}")
    if not dry_run:
        try:
            detach_role_policies(client, role_name)
            delete_inline_policies(client, role_name)
            response = make_api_call(client, "delete_role", RoleName=role_name)
            logger.info(f"Role {role_name} deleted")
            return response
        except Exception as e:
            logger.error(f"Error deleting role {role_name}: {e}")


def detach_role_policy(client, role_name, policy_arn):
    """
    Detach a managed policy from an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to detach the policy from
        policy_arn (string): The ARN of the policy to detach

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Detaching policy {policy_arn} from role: {role_name}")
    if not dry_run:
        try:
            response = make_api_call(
                client, "detach_role_policy", RoleName=role_name, PolicyArn=policy_arn
            )
            logger.info(f"Policy {policy_arn} detached from role {role_name}")
            return response
        except Exception as e:
            logger.error(f"Error detaching policy {policy_arn} from role {role_name}: {e}")


def detach_role_policies(client, role_name):
    """
    Detach all managed policies from an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to detach policies from

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Detaching policies from role: {role_name}")
    if not dry_run:
        try:
            policies = get_role_policies(client, role_name)
            for policy in policies:
                detach_role_policy(client, role_name, policy["PolicyArn"])
            logger.info(f"Policies detached from role {role_name}")
            return
        except Exception as e:
            logger.error(f"Error detaching policies from role {role_name}: {e}")


def delete_inline_policy(client, role_name, policy_name):
    """
    Delete an inline policy from an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to delete the policy from
        policy_name (string): The name of the policy to delete

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Deleting inline policy {policy_name} from role: {role_name}")
    if not dry_run:
        try:
            response = make_api_call(
                client, "delete_role_policy", RoleName=role_name, PolicyName=policy_name
            )
            logger.info(f"Inline policy {policy_name} deleted from role {role_name}")
            return response
        except Exception as e:
            logger.error(f"Error deleting inline policy {policy_name} from role {role_name}: {e}")


def delete_inline_policies(client, role_name):
    """
    Delete all inline policies from an IAM role

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to delete policies from

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Deleting inline policies from role: {role_name}")
    if not dry_run:
        try:
            policies = get_inline_policies(client, role_name)
            for policy in policies:
                delete_inline_policy(client, role_name, policy)
            logger.info(f"Inline policies deleted from role {role_name}")
            return
        except Exception as e:
            logger.error(f"Error deleting inline policies from role {role_name}: {e}")


def restore_role(client, role_name, backup_folder):
    """
    Restore an IAM role from a CloudFormation template

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to restore
        backup_folder (string): The folder containing the backup templates

    Returns:
        Object: The response from the API call
    """
    logger.debug(f"Restoring role: {role_name}")
    sanitized_role_name = re.sub(
        r"[^a-zA-Z0-9-_]", "", role_name.replace(" ", "_").replace("/", "-")
    )
    resource_name = role_name.replace(" ", "").replace("/", "").replace("-", "")
    if not dry_run:
        try:
            role = get_role(client, role_name)
            if role:
                logger.warning(f"Role {role_name} already exists")
                return
            else:
                logger.info(
                    f"Role {role_name} does not exist. Proceeding with restoration."
                )

            # Get list of templates from backup folder for role
            templates = [
                template
                for template in os.listdir(backup_folder)
                if sanitized_role_name in template
            ]
            if not templates:
                logger.error(f"No template found for role {role_name}")
                return

            # Get the latest template
            latest_template = max(
                templates,
                key=lambda t: os.path.getctime(os.path.join(backup_folder, t)),
            )
            with open(os.path.join(backup_folder, latest_template), "r") as file:
                template = json.load(file)

            # Ensure we have the correct sanitized role name key
            role_key = next(
                (key for key in template["Resources"] if key.startswith(resource_name)),
                None,
            )
            if not role_key:
                logger.error(
                    f"No matching role key found in template for {sanitized_role_name}"
                )
                return

            role_template = template["Resources"][role_key]["Properties"]

            # Create the role
            create_role_params = {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": json.dumps(role_template["AssumeRolePolicyDocument"]),
            }

            if "Path" in role_template:
                create_role_params["Path"] = role_template["Path"]

            if "Description" in role_template:
                create_role_params["Description"] = role_template["Description"]

            response = make_api_call(client, "create_role", **create_role_params)
            logger.info(f"Role {role_name} created")

            # Attach managed policies
            if "ManagedPolicyArns" in role_template:
                for policy_arn in role_template["ManagedPolicyArns"]:
                    make_api_call(
                        client,
                        "attach_role_policy",
                        RoleName=role_name,
                        PolicyArn=policy_arn,
                    )
                    logger.info(
                        f"Managed policy {policy_arn} attached to role {role_name}"
                    )

            # Create inline policies
            if "Policies" in role_template:
                for policy in role_template["Policies"]:
                    make_api_call(
                        client,
                        "put_role_policy",
                        RoleName=role_name,
                        PolicyName=policy["PolicyName"],
                        PolicyDocument=json.dumps(policy["PolicyDocument"]),
                    )
                    logger.info(
                        f"Inline policy {policy['PolicyName']} created for role {role_name}"
                    )

            # Tag the role
            if "Tags" in role_template:
                tags = [
                    {"Key": tag["Key"], "Value": tag["Value"]}
                    for tag in role_template["Tags"]
                ]
                make_api_call(client, "tag_role", RoleName=role_name, Tags=tags)
                logger.info(f"Tags added to role {role_name}")

            logger.info(f"Role {role_name} restored")
            return response
        except Exception as e:
            logger.error(f"Error restoring role {role_name}: {e}")
            raise


def main():
    """
    Main function to enable or disable IAM roles based on the arguments passed
    """
    global backup, dry_run, tag_key
    args = parse_arguments()
    roles = read_roles(args.file_path)
    iam_client = boto3.client("iam")
    dry_run = args.dry_run
    tag_key = args.tag_key
    backup = args.backup
    backup_folder = args.backup_folder

    set_log_level("debug" if args.verbose else "info")
    logger.info("Starting Role Disabler")
    logger.info(f"Enabled Options: {args}")

    if args.enable and (args.disable or args.delete or args.restore):
        raise ValueError("Cannot enable and disable/delete/restore roles at the same time.")
    elif args.disable and (args.enable or args.delete or args.restore):
        raise ValueError("Cannot disable and enable/delete/restore roles at the same time.")
    elif args.delete and (args.enable or args.disable or args.restore):
        raise ValueError("Cannot delete and enable/disable/restore roles at the same time.")
    elif args.restore and (args.enable or args.disable or args.delete):
        raise ValueError("Cannot restore and enable/disable/delete roles at the same time.")
    else:
        if backup:
            logger.info("Backing up roles")
            progress_bar = tqdm(total=len(roles), desc="Backing up Roles", unit="role")
            def backup_roles():
                for role_name in roles:
                    backup_role(iam_client, role_name, backup_folder)
                    progress_bar.update(1)
            thread = threading.Thread(target=backup_roles)
            thread.start()
            thread.join()  # Wait for the backup thread to finish before continuing
            logger.info(f"Backup templates saved to {backup_folder}")
            if not args.enable and not args.disable and not args.delete:
                logger.debug("No operation specified. Exiting.")
                return
        if args.enable:
            logger.info("Enabling roles")
            progress_bar = tqdm(total=len(roles), desc="Enabling Roles", unit="role")
            def enable_roles():
                for role_name in roles:
                    enable_role(iam_client, role_name)
                    progress_bar.update(1)
            thread = threading.Thread(target=enable_roles)
            thread.start()
        elif args.disable:
            logger.info("Disabling roles")
            progress_bar = tqdm(total=len(roles), desc="Disabling Roles", unit="role")
            def disable_roles():
                for role_name in roles:
                    disable_role(iam_client, role_name)
                    progress_bar.update(1)
            thread = threading.Thread(target=disable_roles)
            thread.start()
        elif args.delete:
            logger.info("Deleting roles")
            logger.warn(f"Are you sure you want to proceed with deleting {len(roles)} roles?")
            confirm = input("Type 'yes' or 'y' to confirm:")
            if confirm.lower() in ["yes", "y"]:
                progress_bar = tqdm(total=len(roles), desc="Deleting Roles", unit="role")
                def delete_roles():
                    for role_name in roles:
                        delete_role(iam_client, role_name)
                        progress_bar.update(1)
                thread = threading.Thread(target=delete_roles)
                thread.start()
            else:
                logger.info("Deletion canceled.")
                return
        elif args.restore:
            logger.info("Restoring roles")
            progress_bar = tqdm(total=len(roles), desc="Restoring Roles", unit="role")
            def restore_roles():
                for role_name in roles:
                    restore_role(iam_client, role_name, backup_folder)
                    progress_bar.update(1)
            thread = threading.Thread(target=restore_roles)
            thread.start()
        else:
            logger.error("Please specify --enable, --disable, or --delete.")
            raise ValueError("No operation specified.")


if __name__ == "__main__":
    main()
