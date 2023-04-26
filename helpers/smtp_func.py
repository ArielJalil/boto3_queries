# -*- coding: utf-8 -*-

"""Send e-mail via AirNZ SMTP server."""

import logging
import os
import smtplib
import time

from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.mime.multipart import MIMEMultipart

LOGGER = logging.getLogger(__name__)


def smtp_report(body_html, subject, to, cc):
    """Send the report by e-mail."""
    logo = 'files/mercury_logo.png'
    smtp_server = 'smtpgw.mrp.net.nz:25'

    # Create the enclosing (outer) message
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = 'awsoperations@mercury.co.nz'
    msg['To'] = to
    msg['Cc'] = cc
    emaillist = to.split(',') + cc.split(',')

    with open(body_html) as fh:
        msg_content_html = MIMEText(fh.read(), 'html', 'utf-8')

    # Attach company logo to html body
    with open(logo, 'rb') as im:
        img = MIMEBase('image', 'png', filename='img0.png')
        img.add_header('Content-Disposition', 'attachment', filename='img0.png')
        img.add_header('X-Attachment-Id', '1')
        img.add_header('Content-ID', '<1>')
        img.set_payload(im.read())
        encoders.encode_base64(img)

    msg.attach(msg_content_html)
    msg.attach(img)

    try:
        LOGGER.info(f"Sending e-mail via SMTP server {smtp_server} to {emaillist}")
        with smtplib.SMTP(smtp_server) as s:
            s.sendmail(msg['From'], emaillist, msg.as_string())
    except:
        try:
            LOGGER.warning('First attempt of delivery fail -> Retrying.')
            time.sleep(3)
            with smtplib.SMTP(smtp_server) as s:
                s.sendmail(msg['From'], emaillist, msg.as_string())
        except:
            LOGGER.error('E-mail delivery failed.')

    os.remove(body_html)
