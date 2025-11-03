"""
Email Service for sending notifications
"""

import aiosmtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
from datetime import datetime
import os

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
        self.from_email = os.getenv("FROM_EMAIL", "openwatch@example.com")
        self.from_name = os.getenv("FROM_NAME", "OpenWatch Security Scanner")

    async def send_host_offline_alert(
        self, host_name: str, host_ip: str, last_check: datetime, recipients: List[str]
    ) -> bool:
        """Send host offline alert email"""
        if not recipients:
            logger.warning("No recipients provided for host offline alert")
            return False

        subject = f"🚨 Host Offline Alert: {host_name}"

        # Create HTML body
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                    <h2 style="color: #d32f2f; margin-bottom: 20px;">🚨 Host Offline Alert</h2>
                    
                    <div style="background-color: #ffebee; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
                        <p style="margin: 0; font-weight: bold;">A monitored host has gone offline and requires attention.</p>
                    </div>
                    
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                        <tr style="background-color: #f5f5f5;">
                            <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Host Name:</td>
                            <td style="padding: 12px; border: 1px solid #ddd;">{host_name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">IP Address:</td>
                            <td style="padding: 12px; border: 1px solid #ddd;">{host_ip}</td>
                        </tr>
                        <tr style="background-color: #f5f5f5;">
                            <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Last Check:</td>
                            <td style="padding: 12px; border: 1px solid #ddd;">{last_check.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Alert Time:</td>
                            <td style="padding: 12px; border: 1px solid #ddd;">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
                        </tr>
                    </table>
                    
                    <div style="background-color: #e3f2fd; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
                        <h3 style="margin-top: 0; color: #1976d2;">Recommended Actions:</h3>
                        <ul style="margin-bottom: 0;">
                            <li>Check network connectivity to the host</li>
                            <li>Verify SSH service is running on the host</li>
                            <li>Review host logs for any error messages</li>
                            <li>Contact the system administrator if needed</li>
                        </ul>
                    </div>
                    
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                    
                    <p style="font-size: 12px; color: #666; margin: 0;">
                        This is an automated message from OpenWatch Security Scanner. 
                        Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        """

        # Create plain text body as fallback
        plain_body = f"""
HOST OFFLINE ALERT

A monitored host has gone offline and requires attention.

Host Details:
- Host Name: {host_name}
- IP Address: {host_ip}
- Last Check: {last_check.strftime('%Y-%m-%d %H:%M:%S UTC')}
- Alert Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Recommended Actions:
- Check network connectivity to the host
- Verify SSH service is running on the host
- Review host logs for any error messages
- Contact the system administrator if needed

---
This is an automated message from OpenWatch Security Scanner.
        """

        return await self._send_email(recipients, subject, plain_body, html_body)

    async def send_host_online_alert(
        self, host_name: str, host_ip: str, check_time: datetime, recipients: List[str]
    ) -> bool:
        """Send host back online alert email"""
        if not recipients:
            logger.warning("No recipients provided for host online alert")
            return False

        subject = f"✅ Host Online: {host_name}"

        # Create HTML body
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                    <h2 style="color: #388e3c; margin-bottom: 20px;">✅ Host Back Online</h2>
                    
                    <div style="background-color: #e8f5e8; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
                        <p style="margin: 0; font-weight: bold;">A previously offline host is now back online.</p>
                    </div>
                    
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                        <tr style="background-color: #f5f5f5;">
                            <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Host Name:</td>
                            <td style="padding: 12px; border: 1px solid #ddd;">{host_name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">IP Address:</td>
                            <td style="padding: 12px; border: 1px solid #ddd;">{host_ip}</td>
                        </tr>
                        <tr style="background-color: #f5f5f5;">
                            <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">Back Online:</td>
                            <td style="padding: 12px; border: 1px solid #ddd;">{check_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
                        </tr>
                    </table>
                    
                    <div style="background-color: #e8f5e8; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
                        <p style="margin: 0; color: #388e3c;">
                            ✅ The host is now responding to connectivity checks and SSH authentication is working properly.
                        </p>
                    </div>
                    
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                    
                    <p style="font-size: 12px; color: #666; margin: 0;">
                        This is an automated message from OpenWatch Security Scanner. 
                        Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        """

        # Create plain text body as fallback
        plain_body = f"""
HOST BACK ONLINE

A previously offline host is now back online.

Host Details:
- Host Name: {host_name}
- IP Address: {host_ip}
- Back Online: {check_time.strftime('%Y-%m-%d %H:%M:%S UTC')}

The host is now responding to connectivity checks and SSH authentication is working properly.

---
This is an automated message from OpenWatch Security Scanner.
        """

        return await self._send_email(recipients, subject, plain_body, html_body)

    async def _send_email(
        self,
        recipients: List[str],
        subject: str,
        plain_body: str,
        html_body: Optional[str] = None,
    ) -> bool:
        """Send email using SMTP"""
        try:
            # Skip if no SMTP configuration
            if not self.smtp_host or not self.from_email:
                logger.warning("Email not configured (missing SMTP_HOST or FROM_EMAIL)")
                return False

            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = ", ".join(recipients)

            # Add plain text part
            msg.attach(MIMEText(plain_body, "plain"))

            # Add HTML part if provided
            if html_body:
                msg.attach(MIMEText(html_body, "html"))

            # Connect and send
            if self.smtp_use_tls:
                await aiosmtplib.send(
                    msg,
                    hostname=self.smtp_host,
                    port=self.smtp_port,
                    username=self.smtp_username if self.smtp_username else None,
                    password=self.smtp_password if self.smtp_password else None,
                    use_tls=True,
                )
            else:
                await aiosmtplib.send(
                    msg,
                    hostname=self.smtp_host,
                    port=self.smtp_port,
                    username=self.smtp_username if self.smtp_username else None,
                    password=self.smtp_password if self.smtp_password else None,
                )

            logger.info(f"Email sent successfully to {len(recipients)} recipients: {subject}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False


# Global email service instance
email_service = EmailService()
