# Boto3 queries

Use boto3 Python module to run CLI queries on AWS resources within an AWS Organization.

## Required Python modules

* boto3
* botocore
* click

## Query AWS Resources

This python script will run a query of the selected AWS resource across all enabled regions in an Organization using parallel processing code, it certainly runs fast though.

Please update your specific AWS settings in the `helpers/config.py` file before run it:

```bash
$ python3 boto3_query.py --help

Usage: boto3_query.py [OPTIONS]

  Run an AWS resource query by service name.

Options:
  -n, --name [ec2|tag_editor|ami|vpc|vpc_flow_logs|subnet|sec_group|vpce|vpc_peering|vpc_dhcp|tgw|tgw_attach|igw|nat_gw|ebs_volume|ebs_volume_snap|route_table|aws_backup|r53_hosted_zones|ssm_inventory|ssm_patching|aws_config|iam_user|iam_sso_user|iam_sso_group|iam_sso_permission_sets|iam_sso_account_assignments|health|s3_bucket|ram|vpn|dx_vgw|dx_vif]
                                  Query name to run  [default: ec2]
  -a, --account TEXT              AWS Account ID to run the query on.
  --help                          Show this message and exit.                         Show this message and exit.
```

## Author and Lincense:

This script has been written by [Ariel Jall](https://github.com/ArielJalil) and it is released under [GNU 3.0](https://www.gnu.org/licenses/gpl-3.0.en.html).
