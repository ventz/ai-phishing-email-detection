#!/usr/bin/env python3
"""
Display email content from an S3 object to identify which email it is.
"""

import boto3
import email
import argparse
import sys
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from botocore.exceptions import ClientError

def get_email_from_s3(bucket_name, object_key):
    """
    Retrieve an email object from S3 and parse it.
    
    Args:
        bucket_name: S3 bucket name
        object_key: S3 object key
        
    Returns:
        Parsed email message
    """
    try:
        # Get the object from S3
        s3 = boto3.client('s3')
        response = s3.get_object(Bucket=bucket_name, Key=object_key)
        raw_email = response['Body'].read()
        
        # Parse the email content
        email_message = BytesParser(policy=policy.default).parsebytes(raw_email)
        return email_message
    
    except ClientError as e:
        print(f"Error retrieving email from S3: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing email: {str(e)}")
        sys.exit(1)

def extract_original_email(message):
    """
    Extract the original email from a forwarded message.
    
    Args:
        message: The email message to extract from
        
    Returns:
        The original email message or None if not found
    """
    # Initialize a list to collect 'message/rfc822' parts
    message_rfc822_parts = []

    def traverse_message(msg):
        """Recursively traverse message parts to find forwarded content."""
        if msg.get_content_type() == 'message/rfc822':
            payload = msg.get_payload(0)
            message_rfc822_parts.append(payload)
            traverse_message(payload)
        elif msg.is_multipart():
            for part in msg.get_payload():
                traverse_message(part)
        else:
            # Check for application/octet-stream parts with filename ending in '.eml'
            if msg.get_content_type() == 'application/octet-stream':
                filename = msg.get_filename()
                if filename and filename.endswith('.eml'):
                    # Decode and parse the attached .eml file
                    attached_email_bytes = msg.get_payload(decode=True)
                    attached_email = email.message_from_bytes(
                        attached_email_bytes, policy=policy.default)
                    message_rfc822_parts.append(attached_email)
                    traverse_message(attached_email)

    traverse_message(message)

    # Return the last collected 'message/rfc822' part, or None if none found
    if message_rfc822_parts:
        return message_rfc822_parts[-1]
    else:
        return None

def extract_email_body(email_message, max_length=None):
    """
    Extract the body text from an email message.
    
    Args:
        email_message: The email message to extract body from
        max_length: Maximum length of body to return (None for all)
        
    Returns:
        The extracted body text
    """
    body = ""
    
    if email_message.is_multipart():
        # Get preferred body part
        body_part = email_message.get_body(preferencelist=('plain', 'html'))
        if body_part:
            body = body_part.get_content()
        else:
            # Concatenate all text parts
            for part in email_message.walk():
                if part.get_content_type() == 'text/plain':
                    body += part.get_content()
    else:
        # If not multipart, get the payload
        content = email_message.get_payload(decode=True)
        if isinstance(content, bytes):
            body = content.decode(errors='replace')
        else:
            body = str(content)
    
    # Truncate if needed
    if max_length and len(body) > max_length:
        body = body[:max_length] + f"\n\n[... {len(body) - max_length} more characters ...]"
    
    return body

def display_email(bucket_name, object_key, show_body=True, max_body_length=None, raw=False):
    """
    Display email information from an S3 object.
    
    Args:
        bucket_name: S3 bucket name
        object_key: S3 object key
        show_body: Whether to show the email body
        max_body_length: Maximum body length to display
        raw: Whether to display the raw email
    """
    try:
        # Get and parse the email
        email_message = get_email_from_s3(bucket_name, object_key)
        
        if raw:
            # Display raw email as is
            print(email_message)
            return
        
        # Display the S3 information without headers
        print(f"S3 Bucket: {bucket_name}")
        print(f"S3 Object Key: {object_key}")
        print()
        
        # Display the email as is, with only base64 decoding
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                if content_type.startswith('text/'):
                    content = part.get_payload(decode=True)
                    if isinstance(content, bytes):
                        try:
                            print(content.decode(errors='replace'))
                        except Exception as e:
                            print(f"Error decoding content: {str(e)}")
                            print(content)
                    else:
                        print(content)
                elif 'message/rfc822' in content_type:
                    # For forwarded messages
                    for subpart in part.get_payload():
                        if hasattr(subpart, 'as_string'):
                            print(subpart.as_string())
                        else:
                            print(subpart)
        else:
            # For non-multipart messages, decode if necessary
            content = email_message.get_payload(decode=True)
            if isinstance(content, bytes):
                try:
                    print(content.decode(errors='replace'))
                except Exception as e:
                    print(f"Error decoding content: {str(e)}")
                    print(content)
            else:
                print(content)
        
    except Exception as e:
        print(f"Error displaying email: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Display raw email content from an S3 object.")
    parser.add_argument("bucket_name", help="S3 bucket name")
    parser.add_argument("object_key", help="S3 object key")
    parser.add_argument("--body", action="store_true", default=True, 
                        help="Show email body (default: True)")
    parser.add_argument("--no-body", action="store_false", dest="body",
                        help="Don't show email body")
    parser.add_argument("--max-body", type=int, default=None,
                        help="Maximum length of body to display (default: no limit)")
    parser.add_argument("--raw", action="store_true", default=False,
                        help="Display completely unformatted email")
    
    args = parser.parse_args()
    
    display_email(args.bucket_name, args.object_key, args.body, args.max_body, args.raw)
