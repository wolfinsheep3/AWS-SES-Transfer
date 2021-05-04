# https://machinanette.com/2019/06/28/amazon-ses%E3%82%92%E4%BD%BF%E3%81%A3%E3%81%A6%E7%8B%AC%E8%87%AA%E3%83%89%E3%83%A1%E3%82%A4%E3%83%B3%E3%81%AE%E3%83%A1%E3%83%BC%E3%83%AB%E3%82%92gmail%E3%81%A7%E5%8F%97%E3%81%91%E5%8F%96%E3%82%8B-2/

import email
import json
import logging
import os
import re

import boto3
from botocore.exceptions import ClientError

FORWARD_MAPPING = {
    os.environ.get('MSG_TARGET'): os.environ.get('MSG_TO_LIST'),
}

MSG_TARGET_LIST = os.environ.get('MSG_TARGET_LIST', '')

if MSG_TARGET_LIST:
    FORWARD_MAPPING = {}

    for target in MSG_TARGET_LIST.split(','):
        FORWARD_MAPPING[target] = os.environ.get('MSG_TO_LIST')

VERIFIED_FROM_EMAIL = os.environ.get('VERIFIED_FROM_EMAIL', 'noreply@example.com')  # An email that is verified by SES to use as From address.
SUBJECT_PREFIX = os.environ.get('SUBJECT_PREFIX')
SES_INCOMING_BUCKET = os.environ['SES_INCOMING_BUCKET']  # S3 bucket where SES stores incoming emails.

s3 = boto3.client('s3')
ses = boto3.client('ses')

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    record = event['Records'][0]
    assert record['eventSource'] == 'aws:ses'

    o = s3.get_object(Bucket=SES_INCOMING_BUCKET, Key=record['ses']['mail']['messageId'])
    raw_mail = o['Body'].read()
    msg = email.message_from_bytes(raw_mail)
    original_from = msg['From']
    logger.info("body: {}".format(type(raw_mail)))
    logger.info("msg: {}".format(msg))

    del msg['DKIM-Signature']
    del msg['Sender']
    del msg['From']
    del msg['Reply-To']
    del msg['Return-Path']

    logger.info("keys: {}".format(msg.keys()))
    logger.info("from: {}".format(msg['From']))
    logger.info("subject prefix: {}".format(SUBJECT_PREFIX))
    
    msg['From'] = re.sub(r'\<.+?\>', '', original_from).strip() + ' <{}>'.format(VERIFIED_FROM_EMAIL)
    msg['Reply-To'] = VERIFIED_FROM_EMAIL
    msg['Return-Path'] = VERIFIED_FROM_EMAIL
    
    if SUBJECT_PREFIX and SUBJECT_PREFIX.lower() not in msg.get('Subject').lower():
        new_subj = ' '.join([SUBJECT_PREFIX, msg.get('Subject', '')])
        del msg['Subject']

    logger.info("forwarding map: {}".format(FORWARD_MAPPING))

    for recipient in record['ses']['receipt']['recipients']:
        msg['Subject'] = "{} from: {} to {}".format(new_subj, original_from, recipient)
        logger.info("new subject: {}".format(msg['Subject']))
        msg_string = msg.as_string()
        
        logger.info("recipient: {}".format(recipient))
        forwards = FORWARD_MAPPING.get(recipient, '')

        if not forwards:
            logger.warning('Recipent <{}> is not found in forwarding map. Skipping recipient.'.format(recipient))
            continue

        for address in forwards.split(','):
            logger.info("addr: {}".format(address))

            try:
                o = ses.send_raw_email(Destinations=[address], RawMessage=dict(Data=msg_string))
                logger.info('Forwarded email for <{}> to <{}>. SendRawEmail response={}'.format(recipient, address, json.dumps(o)))
            except ClientError as e: 
                logger.error('Client error while forwarding email for <{}> to <{}>: {}'.format(recipient, address, e))
