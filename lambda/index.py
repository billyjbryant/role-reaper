import time
import argparse
import signal
import json
import datetime
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import boto3
import botocore.exceptions as botoexceptions
import pandas as pd
import logging
import structlog
import re

# Create an IAM client
iam_client = boto3.client("iam")
ec2_client = boto3.client("ec2")

# Populate list of AWS Regions
aws_regions = []

# Set default values for arguments
dry_run = debug = lambda_mode = quiet = False
output_format = "table"
output_file = bucket = bucket_folder = None
tag_key = "RoleReaper"
acceptable_formats = ["json", "csv", "table", "txt", "md"]

# Define the roles data list
roles_data = []

# Define the stack exists cache
role_to_stack_map = {}
stack_exists_cache = {}

logger = structlog.getLogger(tag_key)


def set_log_level(log_level: str = "INFO"):
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
            if re.match(pattern, log_level, re.IGNORECASE)
        ),
        None,
    )
    LOG_LEVEL = getattr(logging, matched_level, logging.INFO)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(LOG_LEVEL))


def make_api_call(client, method, **kwargs):
    attempts = 0
    max_attempts = 5
    delay = 1  # Start with 1 second

    while attempts < max_attempts:
        try:
            return getattr(client, method)(**kwargs)
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


def get_regions():
    """Get the list of AWS regions

    Returns:
        list: The list of AWS regions
    """
    ec2_client = boto3.client("ec2")
    regions = []
    try:
        logger.info("Getting list of current AWS regions")
        _regions = make_api_call(ec2_client, "describe_regions")
        regions = [region["RegionName"] for region in _regions["Regions"]]
    except Exception as e:
        logger.error(f"Error getting AWS regions: {e}")
    logger.debug(f"AWS Regions: {regions}")
    return regions


def tag_role(client, role_name, key, value):
    """Tag an IAM role with a key and value

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to tag
        key (string): The tag key
        value (string): The tag value
    """
    if not dry_run:
        logger.debug(f"Tagging role {role_name} with key: {key} and value: {value}")
        try:
            make_api_call(
                client,
                "tag_role",
                RoleName=role_name,
                Tags=[{"Key": key, "Value": value}],
            )
        except Exception as e:
            logger.error(f"Error tagging role {role_name}: {e}")


def untag_role(client, role_name, key):
    """Untag an IAM role with a key

    Args:
        client (Object): The IAM client object
        role_name (string): The name of the IAM role to untag
        key (string): The tag key to remove
    """
    if not dry_run:
        logger.debug(f"Untagging role {role_name} with key: {key}")
        try:
            make_api_call(client, "untag_role", RoleName=role_name, TagKeys=[key])
        except Exception as e:
            logger.error(f"Error untagging role {role_name}: {e}")


def disable_role(client, role):
    """Disable an IAM role

    Args:
        client (Object): The IAM client object
        role (dict): The IAM role information
    """
    role_name = role["RoleName"]
    if not dry_run:
        logger.debug(f"Disabling role: {role_name}")
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

        try:
            response = make_api_call(
                client,
                "put_role_policy",
                RoleName=role_name,
                PolicyName="RoleReaperDisablePolicy",
                PolicyDocument=json.dumps(disable_role_policy),
            )
            tag_role(client, role_name, "Disabled", "true")
            tag_role(client, role_name, tag_key, "true")
            logger.info(f"Role {role_name} disabled: {response}")
            role["Disabled"] = True
            return role
        except Exception as e:
            logger.error(f"Error disabling role {role_name}: {e}")


def enable_role(client, role):
    if not dry_run and role["Disabled"] is True:
        role_name = role["RoleName"]
        logger.debug(f"Enabling role: {role_name}")
        try:
            response = make_api_call(
                client,
                "delete_role_policy",
                RoleName=role_name,
                PolicyName="RoleReaperDisablePolicy",
            )
            untag_role(client, role_name, "Disabled")
            logger.info(f"Role {role_name} enabled: {response}")
            role["Disabled"] = False
            return role
        except Exception as e:
            logger.error(f"Error enabling role {role_name}: {e}")


def fetch_stack_resources(cfn_client, stack_name):
    """Fetch resources for a specific CloudFormation stack."""
    try:
        resources = make_api_call(
            cfn_client, "list_stack_resources", StackName=stack_name
        )
        return [
            (res["PhysicalResourceId"], stack_name)
            for res in resources["StackResourceSummaries"]
            if res["ResourceType"] == "AWS::IAM::Role"
        ]
    except Exception as e:
        logger.error(f"Error fetching resources for stack {stack_name}: {e}")
        return []


def get_active_stacks(region_name="us-east-1"):
    """Get active CloudFormation stacks and their IAM role resources for caching."""
    cfn_client = boto3.client("cloudformation", region_name)
    global stack_exists_cache
    role_map = {}
    logger.debug(f"Getting active stacks and their resources in {region_name}")

    try:
        paginator = cfn_client.get_paginator("list_stacks")
        status_filters = [
            "CREATE_IN_PROGRESS",
            "CREATE_COMPLETE",
            "ROLLBACK_IN_PROGRESS",
            "ROLLBACK_FAILED",
            "ROLLBACK_COMPLETE",
            "UPDATE_IN_PROGRESS",
            "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_COMPLETE",
            "UPDATE_ROLLBACK_IN_PROGRESS",
            "UPDATE_ROLLBACK_FAILED",
            "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_ROLLBACK_COMPLETE",
        ]
        pages = paginator.paginate(StackStatusFilter=status_filters)

        with ThreadPoolExecutor(max_workers=3) as executor:
            # Create a future for each stack page to fetch resources
            futures = [
                executor.submit(fetch_stack_resources, cfn_client, stack["StackName"])
                for page in pages
                for stack in page["StackSummaries"]
            ]
            # Collect results from futures
            for future in as_completed(futures):
                for role_name, stack_name in future.result():
                    stack_exists_cache[stack_name] = True
                    role_map[role_name] = stack_name
    except Exception as e:
        logger.error(f"Error getting active stacks in {region_name}: {e}")

    return role_map


def update_role_associations():
    """Update role associations with their respective stacks across all regions."""
    global aws_regions, role_to_stack_map
    logger.info(f"Updating role associations with their respective stacks in {len(aws_regions)} regions")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for region in aws_regions:
            futures.append(executor.submit(get_active_stacks, region))
        
        # Create a progress bar
        progress_bar = tqdm(total=len(futures), desc="Processing Regions", unit="region")
        
        for future in as_completed(futures):
            role_to_stack_map.update(future.result())
            # Update the progress bar
            progress_bar.update(1)
            # Add a small delay to simulate work being done
            time.sleep(0.1)
        
        # Close the progress bar
        progress_bar.close()
    logger.info(f"Number of roles associated with stacks across all regions: {len(role_to_stack_map)}")
    return role_to_stack_map


def is_role_protected(role):
    """Check if the IAM role is protected

    Args:
        role (dict): The IAM role information

    Returns:
        bool: True if the role is protected, False otherwise
    """
    protected_prefixes = [
        "APIGateway",
        "aws-service-role",
        "aws",
        "AWS",
        "AWSCloudFormation",
        "AWSReservedSSO",
        "AWSServiceRole",
        "cdk",
        "cloudfront",
        "service-role",
    ]
    nonprotected_terms = ['test', 'staging', 'tmp', 'demo', 'example']
    for prefix in protected_prefixes:
        for term in nonprotected_terms:
            if term in role["RoleName"]:
                return False
            elif role["RoleName"].startswith(prefix) or role["Path"].startswith(f"/{prefix}"):
                return True


def output_to_file(df, output_format, output_file):
    """Output the data to a file

    Args:
        df (DataFrame): The data to output
        output_format (string): The output format (json, csv, table)
        output_file (string): The output file path
    """
    if output_file:
        if output_format == "md":
            with open(output_file, "w") as f:
                f.write(df.to_markdown(index=False))
        if output_format == "json":
            df.to_json(output_file, orient="records", date_format="iso")
        elif output_format == "csv":
            df.to_csv(output_file, index=False)
        else:
            # Default output to table
            with open(output_file, "w") as f:
                f.write(df.to_string())
        logger.info(f"Output written to file: {output_file}")


def output_to_stdout(df, output_format):
    """Output the data to stdout

    Args:
        df (DataFrame): The data to output
        output_format (string): The output format (json, csv, table)
    """
    global quiet
    # Output formatting
    if not quiet:
        try:
            if output_format == "json":
                print(df.to_json(orient="records", date_format="iso"))
            elif output_format == "csv":
                print(df.to_csv(index=False))
            elif output_format == "md":
                print(df.to_markdown(index=False))
            else:
                # Default output to table
                print(df)
        except BrokenPipeError:
            sys.stderr.close()


def output_to_s3(df, output_format, bucket, bucket_folder, output_file):
    s3_client = boto3.client("s3")
    object_path = f"{bucket_folder}/{output_file}"
    try:
        if output_format == "json":
            s3_client.put_object(
                Bucket=bucket,
                Key=object_path,
                Body=df.to_json(orient="records", date_format="iso"),
            )
        elif output_format == "csv":
            s3_client.put_object(
                Bucket=bucket, Key=object_path, Body=df.to_csv(index=False)
            )
        elif output_format == "md":
            s3_client.put_object(
                Bucket=bucket, Key=object_path, Body=df.to_markdown(index=False)
            )
        else:
            # Default output to table
            s3_client.put_object(Bucket=bucket, Key=object_path, Body=df.to_string())
        logger.info(f"Output written to S3: s3://{bucket}/{object_path}")
    except Exception as e:
        logger.error(f"Error writing output to S3: {e}")


def return_output(df, output_format, output_file):
    """Return the output in the specified format

    Args:
        df (DataFrame): The data to output
        output_format (string): The output format (json, csv, table)
        output_file (string): The output file path

    Returns:
        output: The output in the specified format
    """
    if output_file:
        for fmt, file in zip(output_format, output_file):
            output_to_file(df, fmt, file)
    else:
        output_to_stdout(df, output_format)


def signal_handler(sig, frame):
    """Signal handler to handle SIGINT

    Args:
        sig (int): The signal number
        frame (Object): The frame object
    """
    global roles_data, output_format, output_file
    try:
        logger.error("Keyboard interrupt detected, exiting")
        df = pd.DataFrame(roles_data)
        return_output(df, output_format, output_file)
    except Exception as e:
        logger.error(f"Error handling signal: {e}")
    finally:
        sys.exit(0)


for sig in [signal.SIGINT, signal.SIGTERM]:
    signal.signal(sig, signal_handler)


def stack_exists(stack_name):
    """Check if the CloudFormation stack exists

    Args:
        stack_name (string): The name of the CloudFormation stack

    Returns:
        bool: True if the stack exists, False otherwise
    """
    global stack_exists_cache
    if stack_name in stack_exists_cache:
        return stack_exists_cache[stack_name]
    try:
        cfn_client = boto3.client("cloudformation")
        stack = cfn_client.describe_stacks(StackName=stack_name)
        stack_exists = True if stack else False
        stack_exists_cache[stack_name] = stack_exists
        return stack_exists
    except botoexceptions.ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            logger.error(f"Access denied to check if stack exists: {e}")
            return None
        elif e.response["Error"]["Code"] == "ValidationError":
            logger.error(f"Stack {stack_name} does not exist")
            return False
    except Exception as e:
        logger.error(f"Error checking if stack exists: {e}")
        return None


def extract_tags(role):
    tags = {}
    if "Tags" in role:
        try:
            for tag in role["Tags"]:
                key = tag["Key"]
                value = tag["Value"]
                if key in ["aws:cloudformation:stack-name", "CloudFormationStackName"]:
                    tags["CloudFormationStackName"] = value
                    this_stack_exists = stack_exists(value)
                    if this_stack_exists is True:
                        tags["CloudFormationStackStatus"] = "Active"
                    elif this_stack_exists is False:
                        tags["CloudFormationStackStatus"] = "NonActive"
                    else:
                        tags["CloudFormationStackStatus"] = "Unknown"
                elif re.match(rf"{tag_key}:(.*)", key):
                    match = re.match(rf"{tag_key}:(.*)", key) # Extract the new key
                    new_key = match.group(1) 
                    tags[new_key] = value 
                    untag_role(iam_client, role["RoleName"], new_key) # Remove the old tag
                    tags.pop(key, None)
                else:
                    for tag_key in [
                        "Application",
                        "CostCategory",
                        "DeleteAfter",
                        "Environment",
                        "PendingDeletion",
                        "Production",
                        "ServiceOrganization",
                        "Team",
                    ]:
                        if key.lower() == tag_key.lower():
                            tags[tag_key] = value
                            break
        except Exception as e:
            logger.error(f"Error extracting tags: {e}")
    sorted_tags = dict(sorted(tags.items()))
    return sorted_tags


def continue_prompt():
    """Prompt the user to continue

    Returns:
        bool: True if the user wants to continue, False otherwise
    """
    proceed = input("Do you want to continue? [y/N]: ").strip().lower()
    if proceed not in ["yes", "y"]:
        logger.info("Operation aborted by the user.")
        sys.exit(0)
    return proceed in ["yes", "y"]


def display_banner(options):
    """Print the banner message

    Args:
        options (dict): The options object containing the input parameters
    """
    logger.info(f"Role Reaper - Running in {'Lambda' if options.get('lambda_mode') else 'CLI'} mode")
    logger.info("---")
    logger.info(f"Targeting production roles: {options.get('target_prod')}")
    logger.info(f"Targeting roles in CloudFormation stacks: {options.get('target_stacks')}")
    if options.get("force"):
        logger.warning("Force delete/disable mode enabled - Use with caution!")
    if not options.get("lambda_mode"):
        if options.get("delete"):
            logger.warning(
                "Deleting unused roles - This is not reversible USE WITH CAUTION!"
            )
        elif options.get("disable_roles"):
            logger.warning(
                "Disabling unused roles - This can be reversed by using the 'enable-roles' argument"
            )
        elif options.get("enable_roles"):
            logger.info("Enabling previously disabled roles")
        if not options.get("force") or not options.get("dry_run") or not options.get("lambda_mode"):
            continue_prompt()
    logger.info("---")
    logger.info(f"Output format: {', '.join(options.get('output_format'))}")
    logger.info(f"Output file: {', '.join(options.get('output_file'))}")
    logger.debug(f"Debug mode: {options.get('debug')}")
    logger.debug(f"Dry run mode: {options.get('dry_run')}")
    logger.info("---")


def list_roles_and_details(options):
    """List IAM roles and their details

    Args:
        options (dict): The options object containing the input parameters

    Returns:
        output: The output in the specified format
    """
    global roles_data, stack_exists_cache, aws_regions, role_to_stack_map, dry_run, debug, disable_role
    for key, value in options.items():
        globals()[key] = value

    display_banner(options)

    if not aws_regions:
        aws_regions = get_regions()

    now = datetime.datetime.now(datetime.timezone.utc)
    sixty_days_ago = now - datetime.timedelta(days=60)
    thirty_days = (now + datetime.timedelta(days=30)).strftime("%Y-%m-%d")

    def is_pending_deletion(role_info):
        """Check if the role is pending deletion

        Args:
            role_info (dict): The role information

        Returns:
            bool: True if the role is pending deletion, False otherwise
        """
        return role_info["PendingDeletion"]

    def role_not_used(role_info):
        """Check if the role has not been used recently

        Args:
            role_info (dict): The role information

        Returns:
            bool: True if the role has not been used recently, False otherwise
        """
        return (
            role_info["RoleLastUsed"] == ("Not Used Recently" or None)
            and role_info["CreateDate"] < sixty_days_ago
        )

    def should_disable(role_info):
        """Check if the role should be disabled

        Args:
            role_info (dict): The role information

        Returns:
            bool: True if the role should be disabled, False otherwise
        """
        return disable_roles and role_info["RoleLastUsed"] == ("Not Used Recently" or None) and (is_pending_deletion(role_info) or should_delete(role_info))

    def should_delete(role_info):
        """Check if the role should be deleted

        Args:
            role_info (dict): The role information

        Returns:
            bool: True if the role should be deleted, False otherwise
        """
        if role_info["DeleteAfter"] not in [None, "Not Available"]:
            expired = (
                datetime.datetime.strptime(
                    role_info["DeleteAfter"], "%Y-%m-%d"
                ).replace(tzinfo=datetime.timezone.utc)
                <= now
            )
            if expired:
                logger.warning(
                    f"Role {role_info['RoleName']} has expired as of {role_info['DeleteAfter']} and should be deleted"
                )
                return expired
            elif force and delete:
                logger.warning(
                    f"Role {role_info['RoleName']} has not expired, but should be deleted due to force delete flags"
                )
                return True
        return False

    def is_role_orphaned(role_info):
        """Check if the IAM role is orphaned

        Args:
            role_info (dict): The IAM role information

        Returns:
            bool: True if the role is orphaned, False otherwise
        """
        has_stack = "CloudFormationStackName" in role_info and role_info[
            "CloudFormationStackName"
        ] not in ["Not Available", None, ""]
        stack_inactive = (
            "CloudFormationStackStatus" in role_info
            and role_info["CloudFormationStackStatus"] not in ["Active"]
        )
        has_team = "Team" in role_info and role_info["Team"] not in [
            "Not Available",
            None,
            False,
            "",
        ]
        return not has_stack and not has_team and stack_inactive

    def is_role_production(role_info):
        """Check if the IAM role is a production role

        Args:
            role_info (dict): The IAM role information

        Returns:
            bool: True if the role is a production role, False otherwise
        """
        if "Production" in role_info and role_info["Production"] is not None:
            return role_info["Production"].lower() == "true"
        elif "Environment" in role_info and role_info["Environment"] is not None:
            return role_info["Environment"].lower() == "production"
        elif (
            "CloudFormationStackName" in role_info
            and role_info["CloudFormationStackName"] not in ["Not Available", None, False]
        ):
            return "prod" in role_info["CloudFormationStackName"].lower()
        return False

    def delete_role(client, role):
        """Delete an IAM role

        Args:
            client (Object): The IAM client object
            role (dict): The IAM role information
        """
        if not dry_run:
            logger.info(f"Deleting role: {role['RoleName']}")
            try:
                client.delete_role(RoleName=role["RoleName"])
            except Exception as e:
                logger.error(f"Error deleting role: {e}")

    def should_flag_role(role_info, target_prod, target_stacks):
        is_prod = is_role_production(role_info)
        is_orphan = is_role_orphaned(role_info)
        is_unused = role_not_used(role_info)

        if target_prod and target_stacks:
            return is_unused and is_prod and not is_orphan
        elif target_prod and not target_stacks:
            return is_unused and is_prod and is_orphan
        elif target_stacks and not target_prod:
            return is_unused and not is_prod and not is_orphan
        else:
            return is_unused and not is_prod and is_orphan

    def get_delete_date(delete_on, delete_after):
        """Get the delete date based on the delete_on and delete_after flags

        Args:
            delete_on (string): The delete on date
            delete_after (string): The delete after number of days

        Returns:
            string: The delete date
        """
        if delete_on:
            return datetime.datetime.strptime(delete_on, "%Y-%m-%d").strftime("%Y-%m-%d")
        elif delete_after:
            return (now + datetime.timedelta(days=int(delete_after))).strftime("%Y-%m-%d")
        else:
            return thirty_days

    def get_disable_date(disable_after):
        """Get the disable date based on the disable_after flag

        Args:
            disable_after (string): The disable after number of days

        Returns:
            string: The disable date
        """
        if disable_after:
            return (now + datetime.timedelta(days=int(disable_after))).strftime("%Y-%m-%d")
        else:
            return (now + datetime.timedelta(days=7)).strftime("%Y-%m-%d")

    def process_role(role):
        """
        Process the IAM role based on the target_prod and target_stacks flags

        Args:
            role (dict): The IAM role information
            target_prod (bool): Whether to target production roles
            target_stacks (bool): Whether to target roles in CloudFormation stacks
            disable_roles (bool): Whether to disable roles
            delete (bool): Whether to delete roles
            force (bool): Whether to force delete/disable roles
        """
        global target_prod, target_stacks, disable_roles, delete, force, enable_roles, dry_run
        if is_role_protected(role):
            logger.info(f"Skipping protected role: {role['RoleName']}")
            return None
        logger.debug(f"Getting details for role: {role['RoleName']}")
        role_details = iam_client.get_role(RoleName=role["RoleName"])
        # Extract the role details
        role_info = {
            "RoleName": role_details["Role"]["RoleName"],
            "Arn": role_details["Role"]["Arn"],
            "CloudFormationStackName": role_to_stack_map.get(
                role_details["Role"]["RoleName"], "Not Available"
            ),
            "Orphaned": False,
            "PendingDeletion": False,
            "Deleted": False,
            "DeleteAfter": None,
            "Disabled": False,
            "DisableAfter": None,
            "CreateDate": role_details["Role"]["CreateDate"],
            "RoleLastUsed": role_details["Role"]
            .get("RoleLastUsed", {})
            .get("LastUsedDate", "Not Used Recently"),
        }
        role_info.update(extract_tags(role_details["Role"]))
        role_info["Orphaned"] = is_role_orphaned(role_info)
        logger.debug(f"Role details: {json.dumps(role_info, default=str, indent=2)}")

        # Flag the role based on the target_prod and target_stacks flags
        if should_flag_role(role_info, target_prod, target_stacks):
            logger.debug(
                f"Role {role_info['RoleName']} meets the criteria for deletion"
            )
            role_info["PendingDeletion"] = True
            role_info["DeleteAfter"] = get_delete_date(options.get("delete_on"), options.get("delete_after"))
            role_info["DisableAfter"] = get_disable_date(options.get("disable_after"))
            tag_role(
                iam_client,
                role_info["RoleName"],
                f"{tag_key}:PendingDeletion",
                role_info["PendingDeletion"],
            )
            tag_role(
                iam_client,
                role_info["RoleName"],
                f"{tag_key}:DeleteAfter",
                role_info["DeleteAfter"],
            )
            if role_info["DisableAfter"]:
                tag_role(
                    iam_client,
                    role_info["RoleName"],
                    f"{tag_key}:DisableAfter",
                    role_info["DisableAfter"],
                )
            tag_role(iam_client, role_info["RoleName"], tag_key, "true")
        else:
            logger.debug(
                f"Role {role_info['RoleName']} does not meet the criteria for deletion"
            )

        # Check if the role should be enabled
        if enable_roles and role_info["Disabled"] is True:
            role_info.update(enable_role(iam_client, role_info))

        # Check if the role is pending deletion after processing
        if is_pending_deletion(role_info):
            logger.info(
                f"Role {role_info['RoleName']} is pending deletion on {role_info['DeleteAfter']}"
            )
            if role_info["RoleLastUsed"] != "Not Used Recently" or None:
                logger.info(
                    f"Role {role_info['RoleName']} was used recently, untagging for deletion"
                )
                role_info["PendingDeletion"] = False
                role_info["DeleteAfter"] = None
                role_info["DisableAfter"] = None
                role_info["Deleted"] = False
                role_info["Disabled"] = False
                untag_role(
                    iam_client, role_info["RoleName"], f"{tag_key}:PendingDeletion"
                )
                untag_role(iam_client, role_info["RoleName"], f"{tag_key}:DeleteAfter")
                untag_role(iam_client, role_info["RoleName"], f"{tag_key}:Deleted")
                untag_role(iam_client, role_info["RoleName"], f"{tag_key}:DisableAfter")
                untag_role(iam_client, role_info["RoleName"], f"{tag_key}:Disabled")
                untag_role(iam_client, role_info["RoleName"], tag_key)
            if should_delete(role_info):
                if delete and not dry_run:
                    if (
                        is_role_production(role_info) and target_prod
                    ) or not is_role_production(role_info):
                        delete_role(iam_client, role_info)
                        role_info["Deleted"] = True
                elif delete and dry_run:
                    logger.warning(
                        f"Role {role_info['RoleName']} is ready for deletion, skipped in dry-run mode"
                    )
                    role_info["Deleted"] = False
            elif should_disable(role_info):
                if disable_roles and not dry_run:
                    role_info.update(disable_role(iam_client, role_info))
                elif disable_roles and dry_run:
                    logger.warning(
                        f"Will disable role {role_info['RoleName']}, skipped in dry-run mode"
                    )
                    role_info["Disabled"] = False
            else:
                logger.warning(
                    f"Role {role_info['RoleName']} is not ready for deletion"
                )
                role_info["Deleted"] = False
                role_info["Disabled"] = False

        target_keys = [
            "RoleName",
            "Arn",
            "CloudFormationStackName",
            "Orphaned",
            "PendingDeletion",
            "Deleted",
            "DeleteAfter",
            "CreateDate",
            "RoleLastUsed",
        ]
        target_info = {k: role_info[k] for k in target_keys}
        sorted_info = {
            k: role_info[k] for k in sorted(role_info) if k not in target_keys
        }
        sorted_role_info = {**target_info, **sorted_info}
        return sorted_role_info

    # Update the role associations with their respective stacks
    update_role_associations()

    # Paginator for the list_roles call
    logger.info("Listing IAM Roles")
    paginator = iam_client.get_paginator("list_roles")
    roles = []

    for page in paginator.paginate():
        roles.extend(page["Roles"])

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_role, role): role for role in roles}
        for future in as_completed(futures):
            role = futures[future]
            try:
                data = future.result()
                if data:
                    roles_data.append(data)
            except Exception as e:
                logger.error(f"Error processing role {role['RoleName']}: {e}")

    roles_data.sort(key=lambda x: x["RoleName"])

    df = pd.DataFrame(roles_data)
    if lambda_mode:
        output_to_s3(df, output_format, bucket, bucket_folder, output_file)
    else:
        return_output(df, output_format, output_file)


def lambda_handler(event, context):
    """Lambda function to list IAM roles and their details

    Args:
        event (Object): The Lambda event object
        context (Object): The Lambda context object
    """
    now = datetime.datetime.now()
    formatted_timestamp = now.strftime("%Y-%m-%d-%H-%M-%S")

    options = {
        "bucket": os.getenv("BUCKET_NAME", None),
        "bucket_folder": os.getenv("BUCKET_FOLDER", "role-reaper"),
        "debug": os.getenv("DEBUG", False),
        "delete": os.getenv("DELETE", False),
        "disable_roles": os.getenv("DISABLE_ROLES", False),
        "enable_roles": os.getenv("ENABLE_ROLES", False),
        "delete_on": os.getenv("DELETE_ON", None),
        "delete_after": os.getenv("DELETE_AFTER", None),
        "disable_after": os.getenv("DISABLE_AFTER", None),
        "disable_on": os.getenv("DISABLE_ON", None),
        "github_token": os.getenv("GITHUB_TOKEN", None),
        "output_file": os.getenv("OUTPUT_FILE", []),
        "output_format": os.getenv("OUTPUT_FORMAT", "json").lower().strip().split(","),
        "quiet": os.getenv("QUIET", True),
        "tag_key": os.getenv("TAG_KEY", "RoleReaper"),
        "target_prod": os.getenv("TARGET_PROD", False),
        "target_stacks": os.getenv("TARGET_STACKS", False),
        "lambda_mode": True,
    }
    for idx, fmt in enumerate(options.get("output_format")):
        if fmt not in acceptable_formats:
            logger.error(
                f"Invalid output format: {fmt}! Valid options are: {', '.join(acceptable_formats)}"
            )
            sys.exit(1)
        elif fmt == "table":
            options.get("output_format")[idx] = "txt"  # Replace 'table' with 'txt'
    if not options.get("output_file"):
        options["output_file"] = [
            f"role-reaper-results-{formatted_timestamp}.{fmt}" for fmt in options.get("output_format")
        ]
    else:
        options["output_file"] = [file.strip() for file in options.get("output_file").split(",")]
    
    if options.get("bucket"):
        options["object_path"] = f"s3://{options.get('bucket')}/{options.get('bucket_folder')}/{options.get('output_file')}"

    if options.get("debug"):
        logger.setLevel(logging.DEBUG)
    elif options.get("quiet"):
        logger.setLevel(logging.ERROR)

    if options.get("disable_roles") and options.get("enable_roles"):
        logger.error("Cannot disable and enable roles at the same time")
        sys.exit(1)
    elif options.get("disable_roles") and options.get("delete"):
        logger.error("Cannot disable and delete roles at the same time")
        sys.exit(1)
    elif options.get("delete") and options.get("enable_roles"):
        logger.error("Cannot delete and enable roles at the same time")
        sys.exit(1)

    display_banner(options)

    list_roles_and_details(options)


if __name__ == "__main__":
    """Main function to list IAM roles and their details

    Returns:
        output: The output in the specified format
    """
    parser = argparse.ArgumentParser(
        description="List AWS IAM Roles and output in various formats."
    )
    parser.add_argument(
        "-b",
        "--bucket",
        help="S3 bucket to store the output",
        default=os.getenv("BUCKET_NAME", None),
    )
    parser.add_argument(
        "-f",
        "--force",
        help="Force delete/disable unused roles",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-F",
        "--bucket-folder",
        help="S3 bucket folder to store the output",
        default=os.getenv("BUCKET_FOLDER", "role-reaper"),
    )
    parser.add_argument(
        "-C",
        "--ci-cd",
        help="Run in CI/CD mode",
        action="store_true",
        default=os.getenv("CI_CD", False),
    )
    parser.add_argument(
        "-D",
        "--delete",
        help="Delete unused roles",
        action="store_true",
        default=os.getenv("DELETE", False),
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        help="Dry run mode",
        action="store_true",
        default=os.getenv("DRY_RUN", False),
    )
    parser.add_argument(
        "-g",
        "--github-token",
        help="GitHub token for CI/CD mode",
        default=os.getenv("GITHUB_TOKEN", None),
    )
    parser.add_argument(
        "-L",
        "--lambda-mode",
        help="Run in Lambda mode",
        action="store_true",
        default=os.getenv("LAMBDA", False),
    )
    parser.add_argument(
        "-o",
        "--output-format",
        help=f"Output format {', '.join(acceptable_formats)}. Comma separated for multiple formats. Default: table",
        default=os.getenv("OUTPUT_FORMAT", "table"),
    )
    parser.add_argument(
        "-P",
        "--target-prod",
        help="Target production roles",
        action="store_true",
        default=os.getenv("TARGET_PROD", False),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        help="Quiet mode",
        action="store_true",
        default=os.getenv("QUIET", False),
    )
    parser.add_argument(
        "-S",
        "--target-stacks",
        help="Target roles in CloudFormation stacks",
        action="store_true",
        default=os.getenv("TARGET_STACKS", False),
    )
    parser.add_argument(
        "-t",
        "--tag-key",
        help="Tag key to use for tagging roles",
        default=os.getenv("TAG_KEY", "RoleReaper"),
    )
    parser.add_argument(
        "-v",
        "--debug",
        help="Enable debug logging",
        action="store_true",
        default=os.getenv("DEBUG", False),
    )
    parser.add_argument(
        "-w",
        "--output-file",
        help="Output file path. If not provided, output will be printed to stdout [Comma separated for multiple formats]",
        default=os.getenv("OUTPUT_FILE", None),
    )
    parser.add_argument(
        "-X",
        "--disable-roles",
        help="Disable unused roles",
        action="store_true",
        default=os.getenv("DISABLE_ROLES", False),
    )
    parser.add_argument(
        "-E",
        "--enable-roles",
        help="Enable disabled roles",
        action="store_true",
        default=os.getenv("ENABLE_ROLES", False),
    )
    parser.add_argument(
        "--delete-on",
        help="Delete roles on a specific date (YYYY-MM-DD)",
        default=os.getenv("DELETE_ON", None),
    )
    parser.add_argument(
        "--delete-after",
        help="Delete roles after a specific number of days",
        default=os.getenv("DELETE_AFTER", None),
    )
    parser.add_argument(
        "--disable-on",
        help="Disable roles on a specific date (YYYY-MM-DD)",
        default=os.getenv("DISABLE_ON", None),
    )
    parser.add_argument(
        "--disable-after",
        help="Disable roles after a specific number of days",
        default=os.getenv("DISABLE_AFTER", None),
    )
    parser.add_argument(
        '--exclude-patterns',
        help='Comma separated list of patterns to exclude from role reaping',
        default=os.getenv("EXCLUDE_PATTERNS", None),
    )
    args = parser.parse_args()
    now = datetime.datetime.now()
    formatted_timestamp = now.strftime("%Y-%m-%d-%H-%M-%S")

    options = {
        **args.__dict__,
        "context": None,
        "event": None,
    }

    options['output_format'] = args.output_format.lower().strip().split(",")
    options["output_file"] = args.output_file.split(",") if args.output_file else []

    if len(options["output_format"]) < len(options["output_file"]):
        for file in options["output_file"]:
            if file.split(".")[-1] not in options['output_format']:
                options['output_format'].append(file.split(".")[-1])

    for fmt in options['output_format']:
        if fmt not in acceptable_formats:
            logger.error(
                f"Invalid output format: {fmt}! Valid options are: {', '.join(acceptable_formats)}"
            )
            sys.exit(1)
        elif fmt == "table":
            options["output_format"][output_format.index(fmt)] = "txt"

    if len(options["output_file"]) < len(options["output_format"]):
        options["output_file"] = [
            f"role-reaper-results-{formatted_timestamp}.{fmt}"
            for fmt in options["output_format"]
        ]

    if options.get("debug"):
        set_log_level("DEBUG")
        logger.debug(f"Options: {options}")
    elif options.get("quiet"):
        set_log_level("ERROR")

    if options.get("disable_roles") and options.get("enable_roles"):
        logger.error("Cannot disable and enable roles at the same time")
        sys.exit(1)
    elif options.get("disable_roles") and options.get("delete"):
        logger.error("Cannot disable and delete roles at the same time")
        sys.exit(1)
    elif options.get("delete") and options.get("enable_roles"):
        logger.error("Cannot delete and enable roles at the same time")
        sys.exit(1)

    list_roles_and_details(options)
