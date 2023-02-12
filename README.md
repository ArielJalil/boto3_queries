# Boto3 queries

Use boto3 Python module to run CLI queries on AWS resources with an AWS Organization.

## Query EC2 instances

This python script will run a query of all EC2 instances across all enabled regions in an Organization using parallel processing code, it certainly runs fast though.

Please update update your specific details in the `__init__.py` file before run it:

```bash
$ python3 query_ec2_instances.py
```

**Note:** This script can be used as a pattern to build any AWS resource query with little effort.

## Author and Lincense:

This script has been written by [Ariel Jall](https://github.com/ArielJalil) and it is released under [GNU 3.0](https://www.gnu.org/licenses/gpl-3.0.en.html).