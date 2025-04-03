# Welcome to Role Reaper

Role Reaper is a Python script that helps remove AWS IAM Roles that are no longer in use. It does this by checking the last time a role was used and if it has not been used in a certain amount of time, and meets other specified criteria it will mark the role for deletion, subsequent executions will delete roles marked for deletion.

Role Reaper is intended to be automated as a Lambda function; however, as of now it must be executed manually.

## Requirements

- [Python 3.12 or higher](https://www.python.org/downloads/)
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) configured with appropriate permissions
- [Poetry](https://python-poetry.org/docs/#installation)

## Installation

1. Clone the repository
1. Change directory to the cloned repository

   ```sh
   cd role-reaper
   ```

1. Install the required packages

   ```sh
   poetry install
   ```

1. Configure your AWS credentials using the AWS CLI

   ```sh
   aws configure
   ```

1. Run the script with Poetry

   ```sh
   poetry run role-disabler
   ```

## Usage

There are two command line tools that can be used to run the script with different outcomes.

- `lambda/roleDisabler.py` - This script will disable roles that meet the criteria specified as command line arguments or environment variables.
- `lambda/index.py` - This script will delete roles that meet the criteria specified as command line arguments or environment variables.
  
### roleDisabler

#### Command Line Arguments (roleDisabler)

##### Required Arguments

- `file_path`: Path to the file containing role names (txt, csv, json).

##### Optional Arguments

- `--backup-folder`: Folder to save CloudFormation templates of roles before disabling. Default: `./backup-templates`
- `--backup`: Backup the roles before disabling.
- `--enable`: Enable the specified roles.
- `--disable`: Disable the specified roles.
- `--delete`: Delete the specified roles.
- `--restore`: Restore the specified roles from backup.
- `-d, --dry-run`: Print actions without executing.
- `-k, --tag-key`: Tag key to use for tracking disabled roles. Default: `RoleReaper`
- `-v, --verbose`: Enable debug logging.

#### Default Behavior

If no command flags are specified, the script will perform the following actions by default:

- The script will read the `file_path` to retrieve the list of IAM roles.
- It will not perform any action (`--enable`, `--disable`, `--delete`, `--restore`) unless specified.
- It will not backup the roles (`--backup`) unless specified.
- The log level will be set to `INFO` unless `-v` or `--verbose` is specified.
- The default tag key is `RoleReaper` unless overridden by `-k` or `--tag-key`.

#### Environment Variables

- `DEBUG`: If set, enables verbose logging.

#### Examples

##### Enable Roles

```sh
python lambda/roleDisabler.py roles_to_enable.txt --enable
```

##### Disable Roles with Backup

```sh
python lambda/roleDisabler.py roles_to_disable.txt --disable --backup
```

##### Delete Roles

```sh
python lambda/roleDisabler.py roles_to_delete.txt --delete
```

##### Restore Roles from Backup

```sh
python lambda/roleDisabler.py roles_to_restore.txt --restore
```

#### Command Line Interface

```sh
usage: lambda/roleDisabler.py [-h] [--backup-folder BACKUP_FOLDER] [--backup] [--enable] [--disable] [--delete] [--restore] [-d] [-k TAG_KEY] [-v] file_path

Enable or Disable AWS IAM Roles.

positional arguments:
  file_path             Path to the file containing role names (txt, csv, json).

optional arguments:
  -h, --help            show this help message and exit
  --backup-folder BACKUP_FOLDER
                        Folder to save CloudFormation templates of roles before disabling.
  --backup              Backup the roles before disabling.
  --enable              Enable the specified roles.
  --disable             Disable the specified roles.
  --delete              Delete the specified roles.
  --restore             Restore the specified roles from backup.
  -d, --dry-run         Print actions without executing.
  -k TAG_KEY, --tag-key TAG_KEY
                        Tag key to use for tracking disabled roles.
  -v, --verbose         Enable debug logging.
```

#### Notes

- The script ensures that only one operation (enable, disable, delete, restore) is performed at a time.
- The backup option creates CloudFormation templates of roles before making any changes.
- The `dry-run` option allows you to see the actions that would be performed without actually executing them.
- The `verbose` option enables debug logging for detailed output.

### Restoring Previously Deleted Roles

There have been several executions of the script that have deleted roles. The backup templates for these roles can be found in the [`backup-templates`](./lambda/backup-templates/) folder.

To restore a role from backup, follow these steps:

1. Identify the role you want to restore from the `backup-templates` directory.
   1. Example role:  
   `acm-staging-CertificateManagerRole-1BARRKHX7I2DE-20240515-164650.template.json`
2. Create a txt file in the `lambda/recovered-roles` directory that contains within it the name of the role(s) you want to restore as it is named in the `backup-templates` directory (without the appended date).
   1. Example txt file name:  
   `recovered-roles-<date>.txt`
      1. Example file contents:  
      `acm-staging-CertificateManagerRole-1BARRKHX7I2DE`  
      `<role-name-2>`  
3. Make sure you have you have your environment set via the aws cli
   1. You can use `aws sts get-caller-identity` to check
4. From the `lambda` direcotry run the `roleDisabler.py` script with the `--restore` flag and the path to the text file you created.
   1. Example  
    `python roleDisabler.py recovered-roles/recovered-roles-<date>.txt --restore`
5. The script will restore the role from the backup template using CloudFormation.
   1. Receiving output similar to the following for each role  
   `<date> <time> [info     ] Role acm-staging-CertificateManagerRole-1BARRKHX7I2DE restored`
6. When all roles have been recovered within the file - Add, commit, and push the new file to keep track of recovered roles

### Main Script (index.py)

The main script `index.py` can be used to list, enable, disable, or delete IAM roles based on various criteria. It is designed to be run in Lambda.

<details><summary>Click to expand for more details</summary>.

#### Command Line Arguments

##### Required

- None

##### Optional

- `-b, --bucket`: S3 bucket to store the output. Default: None.
- `-f, --force`: Force delete/disable unused roles. Default: False.
- `-F, --bucket-folder`: S3 bucket folder to store the output. Default: `role-reaper`.
- `-C, --ci-cd`: Run in CI/CD mode. Default: False.
- `-D, --delete`: Delete unused roles. Default: False.
- `-d, --dry-run`: Dry run mode. Default: False.
- `-g, --github-token`: GitHub token for CI/CD mode. Default: None.
- `-L, --lambda-mode`: Run in Lambda mode. Default: False.
- `-o, --output-format`: Output format (json, csv, table, txt, md). Comma-separated for multiple formats. Default: `table`.
- `-P, --target-prod`: Target production roles. Default: False.
- `-q, --quiet`: Quiet mode. Default: False.
- `-S, --target-stacks`: Target roles in CloudFormation stacks. Default: False.
- `-t, --tag-key`: Tag key to use for tagging roles. Default: `RoleReaper`.
- `-v, --debug`: Enable debug logging. Default: False.
- `-w, --output-file`: Output file path. If not provided, output will be printed to stdout. Comma-separated for multiple formats. Default: None.
- `-X, --disable-roles`: Disable unused roles. Default: False.
- `-E, --enable-roles`: Enable disabled roles. Default: False.
- `--delete-on`: Delete roles on a specific date (YYYY-MM-DD). Default: None.
- `--delete-after`: Delete roles after a specific number of days. Default: None.
- `--disable-on`: Disable roles on a specific date (YYYY-MM-DD). Default: None.
- `--disable-after`: Disable roles after a specific number of days. Default: None.
- `--exclude-patterns`: Comma-separated list of patterns to exclude from role reaping. Default: None.

#### Default Behavior [index.py]

If no command flags are specified, the script will perform the following actions by default:

- The script will list all IAM roles.
- It will not perform any action (`--enable`, `--disable`, `--delete`) unless specified.
- The log level will be set to `INFO` unless `-v` or `--debug` is specified.
- The default tag key is `RoleReaper` unless overridden by `-t` or `--tag-key`.

#### Environment Variables [index.py]

The script can be configured using the following environment variables:

- `BUCKET_NAME`: S3 bucket to store the output. Default: None.
- `BUCKET_FOLDER`: S3 bucket folder to store the output. Default: `role-reaper`.
- `CI_CD`: Run in CI/CD mode. Default: False.
- `DELETE`: Delete unused roles. Default: False.
- `DRY_RUN`: Dry run mode. Default: False.
- `GITHUB_TOKEN`: GitHub token for CI/CD mode. Default: None.
- `LAMBDA`: Run in Lambda mode. Default: False.
- `OUTPUT_FORMAT`: Output format (json, csv, table, txt, md). Comma separated for multiple formats. Default: `table`.
- `TARGET_PROD`: Target production roles. Default: False.
- `QUIET`: Quiet mode. Default: False.
- `TARGET_STACKS`: Target roles in CloudFormation stacks. Default: False.
- `TAG_KEY`: Tag key to use for tagging roles. Default: `RoleReaper`.
- `DEBUG`: Enable debug logging. Default: False.
- `OUTPUT_FILE`: Output file path. If not provided, output will be printed to stdout. Comma separated for multiple formats. Default: None.
- `DISABLE_ROLES`: Disable unused roles. Default: False.
- `ENABLE_ROLES`: Enable disabled roles. Default: False.
- `DELETE_ON`: Delete roles on a specific date (YYYY-MM-DD). Default: None.
- `DELETE_AFTER`: Delete roles after a specific number of days. Default: None.
- `DISABLE_ON`: Disable roles on a specific date (YYYY-MM-DD). Default: None.
- `DISABLE_AFTER`: Disable roles after a specific number of days. Default: None.
- `EXCLUDE_PATTERNS`: Comma separated list of patterns to exclude from role reaping. Default: None.

#### Example Usage

##### Delete Roles [index.py]

```sh
python lambda/index.py --delete
```

##### Disable Roles with Backup [index.py]

```sh
python lambda/index.py --disable --backup
```

##### Enable Roles [index.py]

```sh
python lambda/index.py --enable
```

##### Use in Lambda Mode

```sh
python lambda/index.py -L
```

#### Command Line Interface [index.py]

```sh
usage: lambda/index.py [-h] [-b BUCKET] [-f] [-F BUCKET_FOLDER] [-C] [-D] [-d] [-g GITHUB_TOKEN] [-L] [-o OUTPUT_FORMAT] [-P] [-q] [-S] [-t TAG_KEY] [-v] [-w OUTPUT_FILE] [-X] [-E] [--delete-on DELETE_ON] [--delete-after DELETE_AFTER] [--disable-on DISABLE_ON] [--disable-after DISABLE_AFTER] [--exclude-patterns EXCLUDE_PATTERNS]

List AWS IAM Roles and output in various formats.

optional arguments:
  -h, --help            show this help message and exit
  -b BUCKET, --bucket BUCKET
                        S3 bucket to store the output
  -f, --force           Force delete/disable unused roles
  -F BUCKET_FOLDER, --bucket-folder BUCKET_FOLDER
                        S3 bucket folder to store the output
  -C, --ci-cd           Run in CI/CD mode
  -D, --delete          Delete unused roles
  -d, --dry-run         Dry run mode
  -g GITHUB_TOKEN, --github-token GITHUB_TOKEN
                        GitHub token for CI/CD mode
  -L, --lambda-mode     Run in Lambda mode
  -o OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                        Output format [json, csv, table, txt, md]. Comma separated for multiple formats. Default: table
  -P, --target-prod     Target production roles
  -q, --quiet           Quiet mode
  -S, --target-stacks   Target roles in CloudFormation stacks
  -t TAG_KEY, --tag-key TAG_KEY
                        Tag key to use for tagging roles
  -v, --debug           Enable debug logging
  -w OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output file path. If not provided, output will be printed to stdout [Comma separated for multiple formats]
  -X, --disable-roles   Disable unused roles
  -E, --enable-roles    Enable disabled roles
  --delete-on DELETE_ON
                        Delete roles on a specific date (YYYY-MM-DD)
  --delete-after DELETE_AFTER
                        Delete roles after a specific number of days
  --disable-on DISABLE_ON
                        Disable roles on a specific date (YYYY-MM-DD)
  --disable-after DISABLE_AFTER
                        Disable roles after a specific number of days
  --exclude-patterns EXCLUDE_PATTERNS
                        Comma separated list of patterns to exclude from role reaping
```

#### Notes [index.py]

- The script ensures that only one operation (enable, disable, delete) is performed at a time.
- The backup option creates CloudFormation templates of roles before making any changes.
- The `dry-run` option allows you to see the actions that would be performed without actually executing them.
- The `debug` option enables verbose logging for detailed output.

</details>

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [AWS](https://aws.amazon.com/) for providing the tools and services to build this project.
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) for the AWS SDK for Python.
- [botocore](https://botocore.amazonaws.com/v1/documentation/api/latest/index.html) for the low-level interface to AWS services.
- [pandas](https://pandas.pydata.org/) for the data manipulation and analysis library.
- [ChatGPT](https://chat.openai.com/) for the AI assistance in generating this README.
