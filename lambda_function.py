"""
AWS Lambda function for phishing email detection using Anthropic Claude via AWS Bedrock.

This Lambda function is triggered when an email is received in an S3 bucket.
It extracts the email content, uses Claude to classify it as phishing or clean,
and sends a response email with the classification and explanation.

Environment Variables:
    SES_EMAIL_SENDER: Email address to use as the sender for response emails
    SES_DOMAIN_NAME: Domain name for SES (used to construct default email addresses)
    SES_PHISHING_EMAIL_RECEIVER: Email address to receive forwarded emails for analysis
    SES_CONFIG_SET_NAME: SES Configuration Set Name for sending emails
    DEFAULT_FORWARDER_CATCH_ALL: Required catch-all email address when forwarder can't be determined
    AI_AWS_ACCESS_KEY_ID: AWS access key ID for Bedrock API
    AI_AWS_SECRET_ACCESS_KEY: AWS secret access key for Bedrock API
    GITHUB_TOKEN: Optional GitHub token for creating issues when emails are sent to catch-all
    GITHUB_REPO_OWNER: Optional GitHub repository owner for issue creation
    GITHUB_REPO_NAME: Optional GitHub repository name for issue creation
"""

import json
import os
import logging
from typing import Tuple, Dict, Any, Optional, List, Union
import boto3
import email
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from botocore.exceptions import ClientError
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set up the Amazon Bedrock client
bedrock_runtime = boto3.client(
    service_name='bedrock-runtime',
    region_name='us-east-1',
    aws_access_key_id=os.environ.get("AI_AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AI_AWS_SECRET_ACCESS_KEY")
)

# Initialize SES client
ses = boto3.client('ses')

# Get environment variables
no_reply_email = os.environ.get('SES_EMAIL_SENDER')
if not no_reply_email:
    # Try to construct from domain name if available
    domain_name = os.environ.get('SES_DOMAIN_NAME')
    if domain_name:
        no_reply_email = f"noreply@{domain_name}"
    else:
        logger.warning("SES_EMAIL_SENDER environment variable not set. Using default.")
        no_reply_email = "noreply@example.com"

# Get the default forwarder catch-all email (required)
default_forwarder_catch_all = os.environ.get('DEFAULT_FORWARDER_CATCH_ALL')
if not default_forwarder_catch_all:
    logger.error("DEFAULT_FORWARDER_CATCH_ALL environment variable not set. This is required!")
    raise ValueError("DEFAULT_FORWARDER_CATCH_ALL environment variable must be set")

# Constants
MODEL_ID = os.environ.get('MODEL', 'us.anthropic.claude-sonnet-4-20250514-v1:0')
DEFAULT_SUBJECT = "No Subject Detected"

# Get SES configuration set name
ses_config_set_name = os.environ.get('SES_CONFIG_SET_NAME', 'AWS-SES-Send-Email')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler function.
    
    Args:
        event: The event dict containing S3 bucket and object information
        context: Lambda context object
        
    Returns:
        Dict with status code and response message
    """
    try:
        logger.info("Processing new email event")
        
        # Extract the S3 bucket and object key from the event
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        object_key = event['Records'][0]['s3']['object']['key']
        
        logger.info(f"Processing email from bucket: {bucket_name}, key: {object_key}")
        
        # Retrieve the email content, original recipient, and original subject from S3
        email_content, original_recipient, original_subject = get_email_content_and_recipient_from_s3(
            bucket_name, object_key
        )
        
        # Classify the email with Claude and determine if it's PHISHING
        classification, is_phishing = classify_email_with_claude(email_content)
        
        logger.info(f"Claude classification result: {'PHISHING' if is_phishing else 'CLEAN'}")
        
        logger.info(f"Classification verdict: {'PHISHING' if is_phishing else 'CLEAN'}")
        
        # Create HTML formatted email
        if is_phishing:
            subject = f"[PHISHING Detected] {original_subject}"
            logger.info(f"Email classified as PHISHING: {original_subject}")
            
            # Create HTML body with styling for phishing email
            body = f"""
            <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 800px;
                        margin: 0 auto;
                        padding: 20px;
                    }}
                    .header {{
                        background-color: #f44336;
                        color: white;
                        padding: 15px;
                        border-radius: 5px;
                        margin-bottom: 20px;
                        text-align: center;
                    }}
                    .section {{
                        background-color: #f9f9f9;
                        padding: 15px;
                        margin-bottom: 20px;
                        border-left: 4px solid #f44336;
                        border-radius: 3px;
                    }}
                    h2 {{
                        color: #d32f2f;
                        border-bottom: 1px solid #eee;
                        padding-bottom: 10px;
                    }}
                    h3 {{
                        color: #d32f2f;
                        font-size: 1.1em;
                        margin-top: 15px;
                        margin-bottom: 10px;
                    }}
                    .red-section {{
                        color: #d32f2f;
                        font-size: 1.1em;
                        font-weight: bold;
                        margin-top: 15px;
                        margin-bottom: 10px;
                    }}
                    .footer {{
                        font-size: 0.9em;
                        color: #777;
                        border-top: 1px solid #eee;
                        margin-top: 30px;
                        padding-top: 10px;
                    }}
                    .analysis-content {{
                        background-color: #f5f5f5;
                        padding: 10px;
                        border-radius: 3px;
                    }}
                    .verdict {{
                        background-color: #ffebee;
                        padding: 10px;
                        border-radius: 3px;
                        margin-bottom: 15px;
                    }}
                    ul {{
                        margin-top: 0;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>⚠️ Phishing Email Detected</h1>
                </div>
                
                <div class="section">
                    <h2>Detailed Analysis</h2>
                    <div class="analysis-content">
                        {classification}
                    </div>
                </div>
                
                <div class="footer">
                    <p>This analysis was performed by the Email Analysis Service using AI.</p>
                    <p>If you have any questions, please contact your IT department.</p>
                </div>
            </body>
            </html>
            """
        else:
            subject = f"[CLEAN] {original_subject}"
            logger.info(f"Email classified as CLEAN: {original_subject}")
            
            # Create HTML body with styling for clean email
            body = f"""
            <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 800px;
                        margin: 0 auto;
                        padding: 20px;
                    }}
                    .header {{
                        background-color: #4CAF50;
                        color: white;
                        padding: 15px;
                        border-radius: 5px;
                        margin-bottom: 20px;
                        text-align: center;
                    }}
                    .section {{
                        background-color: #f9f9f9;
                        padding: 15px;
                        margin-bottom: 20px;
                        border-left: 4px solid #4CAF50;
                        border-radius: 3px;
                    }}
                    h2 {{
                        color: #2E7D32;
                        border-bottom: 1px solid #eee;
                        padding-bottom: 10px;
                    }}
                    h3 {{
                        color: #2E7D32;
                        font-size: 1.1em;
                        margin-top: 15px;
                        margin-bottom: 10px;
                    }}
                    .green-section {{
                        color: #2E7D32;
                        font-size: 1.1em;
                        font-weight: bold;
                        margin-top: 15px;
                        margin-bottom: 10px;
                    }}
                    .footer {{
                        font-size: 0.9em;
                        color: #777;
                        border-top: 1px solid #eee;
                        margin-top: 30px;
                        padding-top: 10px;
                    }}
                    .analysis-content {{
                        background-color: #f5f5f5;
                        padding: 10px;
                        border-radius: 3px;
                    }}
                    .verdict {{
                        background-color: #e8f5e9;
                        padding: 10px;
                        border-radius: 3px;
                        margin-bottom: 15px;
                    }}
                    ul {{
                        margin-top: 0;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>✅ Clean Email Verified</h1>
                </div>
                
                <div class="section">
                    <h2>Detailed Analysis</h2>
                    <div class="analysis-content">
                        {classification}
                    </div>
                </div>
                
                <div class="footer">
                    <p>This analysis was performed by the Email Analysis Service using AI.</p>
                    <p>If you have any questions, please contact your IT department.</p>
                </div>
            </body>
            </html>
            """
        
        # Send the response to the original recipient
        send_email(subject, body, original_recipient, is_html=True)
        
        # If the email was sent to the catch-all address, create a GitHub issue if configured
        if original_recipient == default_forwarder_catch_all:
            logger.info(f"Email sent to catch-all address: {default_forwarder_catch_all}")
            create_github_issue(subject, email_content, is_phishing)
        
        return {
            'statusCode': 200,
            'body': json.dumps('Email processed successfully')
        }
    except Exception as e:
        logger.error(f"Error processing email: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error processing email: {str(e)}')
        }


def process_classification_output(classification: str, is_phishing: bool) -> str:
    """
    Process the classification output from Claude to convert Markdown to HTML.
    
    Args:
        classification: The raw classification output from Claude
        is_phishing: Whether the email was classified as phishing
        
    Returns:
        Processed HTML content
    """
    import re
    
    # Use the passed is_phishing flag to determine section styling
    section_class = 'red-section' if is_phishing else 'green-section'
    
    # Extract the verdict (first line that contains PHISHING or CLEAN)
    lines = classification.strip().split('\n')
    verdict_line = ""
    for line in lines:
        if "PHISHING" in line or "CLEAN" in line:
            # Extract just the classification (PHISHING or CLEAN), ignoring confidence level
            match = re.search(r'(PHISHING|CLEAN)', line)
            if match:
                verdict = match.group(1)
                verdict_line = f"<div class='verdict'><h3>{verdict}</h3></div>"
                break
            else:
                verdict_line = f"<div class='verdict'><h3>{line}</h3></div>"
                break
    
    # Replace section markers with appropriate HTML with the correct class
    # This converts [SECTION]RED FLAGS[/SECTION] into <h3 class="red-section">RED FLAGS</h3>
    processed = re.sub(r'\[SECTION\](.*?)\[/SECTION\]', 
                       lambda m: f'<h3 class="{section_class}">{m.group(1)}</h3>', 
                       classification)
    
    # Extract sections and their content
    sections = {}
    current_section = None
    for line in lines:
        # Check if this is a section header line
        section_match = re.search(r'\[SECTION\](.*?)\[/SECTION\]', line)
        if section_match:
            current_section = section_match.group(1)
            sections[current_section] = []
        elif current_section and line.strip() and not "PHISHING" in line and not "CLEAN" in line:
            # Remove bullet characters from the beginning of lines and convert to proper HTML bullet points
            # First remove any bullet characters (•, *, -, etc.) from the beginning of the line
            cleaned_line = re.sub(r'^\s*[•\*\-]\s*', '', line.strip())
            # Convert **text** to <strong>text</strong> for emphasis
            formatted_line = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', cleaned_line)
            sections[current_section].append(f"<li>{formatted_line}</li>")
    
    # Build the HTML output with the verdict at the top
    result = [verdict_line]
    
    # For PHISHING emails: RED FLAGS and HOW TO IDENTIFY SIMILAR THREATS sections
    if is_phishing:
        # Add RED FLAGS section if it exists
        if "RED FLAGS" in sections and sections["RED FLAGS"]:
            result.append(f"<h3 class='{section_class}'>RED FLAGS</h3>")
            result.append("<ul>")
            result.extend(sections["RED FLAGS"])
            result.append("</ul>")
        
        # Add HOW TO IDENTIFY SIMILAR THREATS section if it exists
        if "HOW TO IDENTIFY SIMILAR THREATS" in sections and sections["HOW TO IDENTIFY SIMILAR THREATS"]:
            result.append(f"<h3 class='{section_class}'>HOW TO IDENTIFY SIMILAR THREATS</h3>")
            result.append("<ul>")
            result.extend(sections["HOW TO IDENTIFY SIMILAR THREATS"])
            result.append("</ul>")
    # For CLEAN emails: CLEAN INDICATORS section
    else:
        # Add CLEAN INDICATORS section if it exists
        if "CLEAN INDICATORS" in sections and sections["CLEAN INDICATORS"]:
            result.append(f"<h3 class='{section_class}'>CLEAN INDICATORS</h3>")
            result.append("<ul>")
            result.extend(sections["CLEAN INDICATORS"])
            result.append("</ul>")
    
    return "\n".join(result)

def classify_email_with_claude(forwarded_email_content: str) -> Tuple[str, bool]:
    """
    Classify an email as phishing or clean using Claude.
    
    Args:
        forwarded_email_content: The content of the forwarded email
        
    Returns:
        Tuple of (processed_classification, is_phishing_flag)
    """
    # Get current date
    from datetime import datetime
    current_date = datetime.now().strftime("%B %d, %Y")
    
    # Define the prompt
    prompt = f"""You are an expert in cybersecurity and email analysis. Analyze the following email and determine whether it is 'PHISHING' or 'CLEAN'.

Begin your response with a clear "PHISHING" or "CLEAN" verdict.

Then provide your analysis in bullet point format as follows:

For PHISHING classification, use these section headings:
[SECTION]RED FLAGS[/SECTION]
[SECTION]HOW TO IDENTIFY SIMILAR THREATS[/SECTION]

For CLEAN classification, use this section heading:
[SECTION]CLEAN INDICATORS[/SECTION]

CRITICAL FORMATTING REQUIREMENTS:
- Create 5-8 separate bullet points for each section
- Each bullet point must be a single sentence
- Each bullet point should cover ONE specific point only
- Write in a direct, concise manner without unnecessary words
- DO NOT write paragraphs - ONLY bullet points

For PHISHING classification:
- RED FLAGS: List specific suspicious elements found in this email (one per bullet)
- HOW TO IDENTIFY SIMILAR THREATS: Provide specific tips for identifying similar phishing attempts (one tip per bullet)

For CLEAN classification:
- CLEAN INDICATORS: List specific reasons why the email appears legitimate (one reason per bullet)

IMPORTANT: Focus ONLY on the ORIGINAL email content. Do NOT mention or analyze:
- Any forwarding chain
- The person who forwarded the email
- The email analysis service itself
- Any details about Organization or the analysis process

Instead, analyze ONLY these aspects of the original email:
- Original sender domain and address
- Email content language, urgency, and grammar
- Links and their destinations in the original email
- Attachments or unusual requests in the original email
- Whether the content appears contextually appropriate

Today's date: {current_date}

Here is the email content for analysis:

{forwarded_email_content}
"""

    # Prepare the request body for Claude
    request_body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2000,
        "temperature": 0.7,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    })
    
    try:
        logger.info(f"Sending request to Bedrock with model: {MODEL_ID}")
        response = bedrock_runtime.invoke_model(
            modelId=MODEL_ID,
            body=request_body
        )
        # Parse the response
        response_body = json.loads(response['body'].read())
        raw_classification = response_body['content'][0]['text']
        
        # Determine if this is a PHISHING email - be much more precise
        is_phishing = False
        
        # More thorough analysis for phishing detection
        lines = raw_classification.strip().split('\n')
        
        # Check for explicit PHISHING or CLEAN verdicts in the first few lines
        explicit_verdict_found = False
        for i in range(min(5, len(lines))):
            line = lines[i].upper().strip()
            if line == "PHISHING":
                is_phishing = True
                explicit_verdict_found = True
                logger.info("Found explicit PHISHING verdict")
                break
            elif line == "CLEAN":
                is_phishing = False
                explicit_verdict_found = True
                logger.info("Found explicit CLEAN verdict") 
                break
        
        # If no explicit verdict was found, check for section markers
        if not explicit_verdict_found:
            if "[SECTION]RED FLAGS[/SECTION]" in raw_classification:
                is_phishing = True
                logger.info("Found RED FLAGS section, treating as PHISHING")
        
        # Final check - if we see 'PHISHING' anywhere in the first 20 lines, consider it phishing
        if not is_phishing:
            for i in range(min(20, len(lines))):
                if "PHISHING" in lines[i].upper():
                    is_phishing = True
                    logger.info("Found PHISHING keyword in first 20 lines")
                    break
            
        logger.info(f"Phishing detection result: {'PHISHING' if is_phishing else 'CLEAN'}")
        
        # Process the classification output to convert Markdown to HTML
        processed_classification = process_classification_output(raw_classification, is_phishing)
        
        return processed_classification, is_phishing
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"Bedrock API error: {error_code} - {error_message}")
        # Default to treating as clean in case of errors
        return f"Error: Unable to process the email content. ({error_code})", False
    except Exception as e:
        logger.error(f"Unexpected error during classification: {str(e)}", exc_info=True)
        # Default to treating as clean in case of errors
        return "Error: Unexpected error occurred during email classification.", False


def get_email_content_and_recipient_from_s3(bucket_name: str, object_key: str) -> Tuple[str, str, str]:
    """
    Retrieve and parse email content from S3.
    
    Args:
        bucket_name: S3 bucket name
        object_key: S3 object key
        
    Returns:
        Tuple containing (formatted_email_content, forwarder_address, subject)
    """
    s3 = boto3.client('s3')

    try:
        # Fetch the email object from S3
        logger.info(f"Retrieving email from S3: {bucket_name}/{object_key}")
        response = s3.get_object(Bucket=bucket_name, Key=object_key)
        raw_email = response['Body'].read()
    except ClientError as e:
        logger.error(f"Error retrieving email from S3: {str(e)}", exc_info=True)
        raise

    # Parse the email content
    email_message = BytesParser(policy=policy.default).parsebytes(raw_email)

    # Get the forwarder's email address
    forwarder_address = email_message.get('From')

    # Extract the original email
    original_email = extract_original_email(email_message)

    # Extract information from the original email
    if original_email:
        # Extract headers from the original email
        spammer_from_address = original_email.get('From')
        spammer_to_address = original_email.get('To')
        subject = original_email.get('Subject')
        body = extract_email_body(original_email)
    else:
        # Use the top-level email headers and body
        spammer_from_address = email_message.get('From')
        spammer_to_address = email_message.get('To')
        subject = email_message.get('Subject')
        body = extract_email_body(email_message)

    # Handle missing values
    forwarder_address = forwarder_address or default_forwarder_catch_all
    subject = subject or DEFAULT_SUBJECT

    # Format the email content
    formatted_email_content = f"""
From: {spammer_from_address or 'N/A'}
To: {spammer_to_address or 'N/A'}
Subject: {subject}

{body}
"""

    return formatted_email_content, forwarder_address, subject


def extract_original_email(message: EmailMessage) -> Optional[EmailMessage]:
    """
    Extract the original email from a forwarded message.
    
    Args:
        message: The email message to extract from
        
    Returns:
        The original email message or None if not found
    """
    # Initialize a list to collect 'message/rfc822' parts
    message_rfc822_parts = []

    def traverse_message(msg: EmailMessage) -> None:
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


def extract_email_body(email_message: EmailMessage) -> str:
    """
    Extract the body text from an email message.
    
    Args:
        email_message: The email message to extract body from
        
    Returns:
        The extracted body text
    """
    if email_message.is_multipart():
        # Get preferred body part
        body_part = email_message.get_body(preferencelist=('plain', 'html'))
        if body_part:
            return body_part.get_content()
        else:
            # Concatenate all text parts
            body = ''
            for part in email_message.walk():
                if part.get_content_type() == 'text/plain':
                    body += part.get_content()
            return body
    else:
        # If not multipart, get the payload
        body = email_message.get_payload(decode=True)
        if isinstance(body, bytes):
            return body.decode(errors='replace')
        else:
            return str(body)


def create_github_issue(subject: str, email_content: str, is_phishing: bool) -> None:
    """
    Create a GitHub issue for emails sent to the catch-all address.
    
    Args:
        subject: Email subject
        email_content: Email content
        is_phishing: Whether the email was classified as phishing
    """
    # Check if GitHub integration is configured
    github_token = os.environ.get('GITHUB_TOKEN')
    github_repo_owner = os.environ.get('GITHUB_REPO_OWNER')
    github_repo_name = os.environ.get('GITHUB_REPO_NAME')
    
    if not all([github_token, github_repo_owner, github_repo_name]):
        logger.info("GitHub integration not configured, skipping issue creation")
        return
    
    try:
        import requests
        
        # Sanitize email content (remove any sensitive information)
        sanitized_content = sanitize_email_content(email_content)
        
        # Create issue title
        issue_title = f"{'[PHISHING]' if is_phishing else '[CLEAN]'} {subject}"
        
        # Create issue body
        issue_body = f"""
## Email Analysis Result

**Classification**: {'PHISHING' if is_phishing else 'CLEAN'}
**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Email Content (Sanitized)

```
{sanitized_content}
```

This issue was automatically created because an email was sent to the catch-all address.
"""
        
        # Create the issue
        url = f"https://api.github.com/repos/{github_repo_owner}/{github_repo_name}/issues"
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        data = {
            "title": issue_title,
            "body": issue_body,
            "labels": ["phishing-email", "catch-all"]
        }
        
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        
        issue_number = response.json().get('number')
        logger.info(f"GitHub issue #{issue_number} created successfully")
        
    except Exception as e:
        logger.error(f"Error creating GitHub issue: {str(e)}", exc_info=True)


def sanitize_email_content(email_content: str) -> str:
    """
    Sanitize email content to remove sensitive information.
    
    Args:
        email_content: Raw email content
        
    Returns:
        Sanitized email content
    """
    import re
    
    # Replace email addresses with [EMAIL]
    sanitized = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL]', email_content)
    
    # Replace phone numbers with [PHONE]
    sanitized = re.sub(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', '[PHONE]', sanitized)
    
    # Replace URLs with [URL]
    sanitized = re.sub(r'https?://\S+', '[URL]', sanitized)
    
    # Replace potential credit card numbers with [CREDIT_CARD]
    sanitized = re.sub(r'\b(?:\d{4}[-\s]?){3}\d{4}\b', '[CREDIT_CARD]', sanitized)
    
    # Replace potential SSNs with [SSN]
    sanitized = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', sanitized)
    
    return sanitized


def send_email(subject: str, body: str, recipient: str, is_html: bool = True) -> Dict[str, Any]:
    """
    Send an email using SES.
    
    Args:
        subject: Email subject
        body: Email body (can be HTML or plain text)
        recipient: Recipient email address
        is_html: Whether the body is HTML (default: True)
        
    Returns:
        SES response
    """
    logger.info(f"Sending email to: {recipient}, Subject: {subject}")
    
    try:
        message = {
            'Subject': {'Data': subject},
            'Body': {}
        }
        
        if is_html:
            message['Body']['Html'] = {'Data': body}
            # Also include a plain text version for email clients that don't support HTML
            # Extract content from HTML, removing all HTML tags and CSS
            import re
            
            # First remove the style section
            plain_text = re.sub(r'<style>.*?</style>', '', body, flags=re.DOTALL)
            
            # Replace common HTML elements with appropriate plain text formatting
            plain_text = plain_text.replace('<br>', '\n').replace('<hr>', '-' * 40)
            plain_text = plain_text.replace('<h1>', '').replace('</h1>', '\n\n')
            plain_text = plain_text.replace('<h2>', '').replace('</h2>', '\n')
            plain_text = plain_text.replace('<h3>', '').replace('</h3>', '\n')
            plain_text = plain_text.replace('<p>', '').replace('</p>', '\n')
            plain_text = plain_text.replace('<strong>', '').replace('</strong>', '')
            plain_text = plain_text.replace('<div>', '').replace('</div>', '\n')
            
            # Remove all remaining HTML tags
            plain_text = re.sub(r'<[^>]*>', '', plain_text)
            
            # Fix spacing issues
            plain_text = re.sub(r'\n\s*\n', '\n\n', plain_text)
            plain_text = re.sub(r' +', ' ', plain_text)
            plain_text = plain_text.strip()
            message['Body']['Text'] = {'Data': plain_text}
        else:
            message['Body']['Text'] = {'Data': body}
        
        response = ses.send_email(
            Source=no_reply_email,
            Destination={'ToAddresses': [recipient]},
            Message=message,
            ConfigurationSetName=ses_config_set_name
        )
        logger.info(f"Email sent successfully, MessageId: {response['MessageId']}")
        return response
    except ClientError as e:
        logger.error(f"Error sending email: {str(e)}", exc_info=True)
        raise
