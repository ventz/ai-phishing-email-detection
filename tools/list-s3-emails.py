#!/usr/bin/env python3
"""
Lists S3 emails from the specified bucket.
"""

import boto3
import argparse
import sys
from datetime import datetime

def list_s3_emails(bucket_name, prefix="", max_items=100, detail_level="basic"):
    """
    List email objects in an S3 bucket.
    
    Args:
        bucket_name: Name of the S3 bucket
        prefix: Optional prefix to filter objects (folder path)
        max_items: Maximum number of items to list
        detail_level: Level of detail to show ('basic' or 'full')
    """
    try:
        # Initialize S3 client
        s3 = boto3.client('s3')
        
        # Get list of objects
        if prefix:
            response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix, MaxKeys=max_items)
        else:
            response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=max_items)
        
        # Check if the bucket is empty or no objects match the prefix
        if 'Contents' not in response:
            print(f"No objects found in bucket '{bucket_name}'" + 
                  (f" with prefix '{prefix}'" if prefix else ""))
            return
        
        # Print header
        print(f"\nListing up to {max_items} emails in bucket: {bucket_name}" + 
              (f" (prefix: {prefix})" if prefix else ""))
        print("-" * 80)
        
        # Sort objects by LastModified timestamp (oldest first, newest last)
        sorted_objects = sorted(response['Contents'], key=lambda x: x['LastModified'])
        
        # Print objects
        for i, obj in enumerate(sorted_objects, 1):
            key = obj['Key']
            size = obj['Size']
            last_modified = obj['LastModified']
            
            # Format timestamp
            timestamp = last_modified.strftime('%Y-%m-%d %H:%M:%S')
            
            if detail_level == "basic":
                print(f"{i}. {key}")
            else:
                size_str = format_size(size)
                print(f"{i}. {key}")
                print(f"   Size: {size_str}")
                print(f"   Last modified: {timestamp}")
                print(f"   Full path: s3://{bucket_name}/{key}")
                print(f"   Use: python trigger-lambda-email.py {bucket_name} {key}")
                print()
        
        print("-" * 80)
        print(f"Total objects: {len(response['Contents'])}")
        
        # Show if there are more objects
        if response.get('IsTruncated'):
            print(f"Note: There are more objects in the bucket. Use --max-items to show more.")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

def format_size(size_bytes):
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024 or unit == 'GB':
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="List email objects in an S3 bucket.")
    parser.add_argument("bucket_name", help="Name of the S3 bucket")
    parser.add_argument("--prefix", help="Optional prefix to filter objects (folder path)", default="")
    parser.add_argument("--max-items", type=int, help="Maximum number of items to list", default=100)
    parser.add_argument("--detail", choices=["basic", "full"], default="full", 
                        help="Level of detail to show (basic or full)")
    
    args = parser.parse_args()
    
    list_s3_emails(args.bucket_name, args.prefix, args.max_items, args.detail)
