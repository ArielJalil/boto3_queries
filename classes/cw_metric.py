# -*- coding: utf-8 -*-
"""Class to handle CloudWatch Metrics."""

from logging  import getLogger
from datetime import datetime, timedelta

LOGGER = getLogger(__name__)

class CwMetric:
    """Manage CloudWatch Metric."""

    def __init__(self, client: object) -> None:
        """Set class variables."""
        self.client = client

    def get_s3_metric(self, bucket: str, metric:str, stg_type: str, statistic='Sum') -> dict:
        """Query S3 Namespace Metric."""
        result = self.client.get_metric_statistics(
            Namespace="AWS/S3",
            Dimensions=[{"Name": "BucketName", "Value": bucket},
                        {"Name": "StorageType", "Value": stg_type}],
            MetricName=metric,
            StartTime=datetime.now() - timedelta(2),
            EndTime=datetime.now(),
            Period=86400,
            Statistics=[statistic],
        )
        try:
            return {
                'Value': result["Datapoints"][0][statistic],
                'Unit': result['Datapoints'][0]['Unit']
            }
        except:
            return {
                'Value': 0,
                'Unit': None
            }

    def get_bucket_size(self, bucket: str) -> dict:
        """Query S3 bucket Standard Storage usage."""
        return self.get_s3_metric(bucket, 'BucketSizeBytes', 'StandardStorage')

    def get_bucket_object_count(self, bucket: str) -> dict:
        """Query S3 bucket Objects count."""
        return self.get_s3_metric(bucket, 'NumberOfObjects', 'AllStorageTypes')

    def display_bucket_size(self, bucket: str) -> None:
        """Display S3 bucket Standard Storage usage."""
        size = self.get_bucket_size(bucket)
        print(f"{bucket}: {int(size['Value'])} {size['Unit']}")

    def display_object_count(self, bucket: str) -> None:
        """Display S3 bucket Standard Storage usage."""
        count = self.get_bucket_object_count(bucket)
        print(f"{bucket}: {int(count['Value'])} Object/s")
