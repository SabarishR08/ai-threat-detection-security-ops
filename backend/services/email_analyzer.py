"""
Advanced Email Analysis & Threat Detection

Extract URLs, QR codes, attachments, check DMARC/SPF/DKIM, detect phishing
"""

import re
import logging
import base64
from typing import Dict, List, Tuple
from email.mime.text import MIMEText
from bs4 import BeautifulSoup
import requests
from io import BytesIO
import cv2
import numpy as np

logger = logging.getLogger(__name__)


class EmailExtractor:
    """Extract components from email"""
    
    @staticmethod
    def extract_urls(email_body: str, email_html: str = None) -> List[Dict]:
        """
        Extract all URLs from email body and HTML
        
        Returns: [{'url': '...', 'context': '...', 'source': 'text'|'html'}]
        """
        urls = []
        
        # Extract from plain text
        url_pattern = r'https?://[^\s\)<>\[\]"\']+|www\.[^\s\)<>\[\]"\']+\.[a-z]{2,}'
        
        if email_body:
            for match in re.finditer(url_pattern, email_body, re.IGNORECASE):
                url = match.group(0)
                if not url.startswith('http'):
                    url = f'https://{url}'
                
                # Get surrounding context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(email_body), match.end() + 50)
                context = email_body[start:end]
                
                urls.append({
                    'url': url,
                    'context': context.strip(),
                    'source': 'text'
                })
        
        # Extract from HTML
        if email_html:
            soup = BeautifulSoup(email_html, 'html.parser')
            
            # Find href attributes
            for link in soup.find_all('a', href=True):
                url = link['href']
                if url.startswith(('http://', 'https://', 'www.')):
                    if not url.startswith('http'):
                        url = f'https://{url}'
                    
                    urls.append({
                        'url': url,
                        'context': link.get_text(strip=True),
                        'source': 'html'
                    })
            
            # Find image src (potential tracking pixels)
            for img in soup.find_all('img'):
                src = img.get('src', '')
                if src.startswith(('http://', 'https://')):
                    urls.append({
                        'url': src,
                        'context': 'Tracking pixel',
                        'source': 'image'
                    })
        
        return urls
    
    @staticmethod
    def extract_qr_codes(email_html: str = None, attachments: List = None) -> List[Dict]:
        """
        Extract QR codes from email HTML and attachments
        
        Returns: [{'type': 'html'|'attachment', 'data': '...', 'context': '...'}]
        """
        qr_codes = []
        
        # Extract from HTML images (base64 embedded)
        if email_html:
            soup = BeautifulSoup(email_html, 'html.parser')
            
            for img in soup.find_all('img'):
                src = img.get('src', '')
                
                # Check if base64 image
                if src.startswith('data:image'):
                    qr_codes.append({
                        'type': 'html_embedded',
                        'data': src,
                        'context': img.get('alt', 'QR Code in email'),
                        'is_base64': True
                    })
        
        # Extract from attachments
        if attachments:
            for attachment in attachments:
                if attachment.get('mime_type', '').startswith('image/'):
                    qr_codes.append({
                        'type': 'attachment',
                        'filename': attachment.get('filename', 'image'),
                        'data': attachment.get('data'),
                        'context': f"Attachment: {attachment.get('filename')}"
                    })
        
        return qr_codes
    
    @staticmethod
    def extract_attachments(email_msg) -> List[Dict]:
        """
        Extract attachment metadata
        
        Returns: [{'filename': '...', 'mime_type': '...', 'size': 0, 'safe': bool}]
        """
        attachments = []
        
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.msi', '.com', '.pif',
                               '.vbs', '.js', '.jar', '.zip', '.rar', '.iso', '.dmg']
        dangerous_mimes = ['application/x-executable', 'application/x-msdownload',
                          'application/x-msdos-program', 'application/x-wine-extension-msp']
        
        # This would process actual email attachments
        # Placeholder for structure
        
        return attachments
    
    @staticmethod
    def extract_headers(email_msg) -> Dict:
        """Extract email headers for authentication checks"""
        return {
            'from': email_msg.get('From', ''),
            'from_domain': email_msg.get('From', '').split('@')[-1] if '@' in email_msg.get('From', '') else '',
            'reply_to': email_msg.get('Reply-To', ''),
            'return_path': email_msg.get('Return-Path', ''),
            'received': email_msg.get('Received', ''),
            'date': email_msg.get('Date', '')
        }


class EmailAuthChecker:
    """Check email authentication records"""
    
    @staticmethod
    def check_dmarc(domain: str) -> Dict:
        """Check DMARC record"""
        try:
            # DMARC record: _dmarc.domain.com
            import dns.resolver
            
            records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc_record = str(records[0]).strip('"')
            
            return {
                'found': True,
                'record': dmarc_record,
                'passes': 'p=reject' in dmarc_record or 'p=quarantine' in dmarc_record,
                'policy': 'strict' if 'p=reject' in dmarc_record else 'quarantine' if 'p=quarantine' in dmarc_record else 'none'
            }
        except Exception as e:
            logger.warning(f"DMARC check failed: {e}")
            return {'found': False, 'passes': False, 'policy': 'none'}
    
    @staticmethod
    def check_spf(domain: str) -> Dict:
        """Check SPF record"""
        try:
            import dns.resolver
            
            records = dns.resolver.resolve(domain, 'TXT')
            spf_records = [str(r).strip('"') for r in records if 'v=spf1' in str(r)]
            
            if spf_records:
                return {
                    'found': True,
                    'record': spf_records[0],
                    'passes': True
                }
        except Exception as e:
            logger.warning(f"SPF check failed: {e}")
        
        return {'found': False, 'passes': False}
    
    @staticmethod
    def check_dkim(domain: str, selector: str = 'default') -> Dict:
        """Check DKIM record"""
        try:
            import dns.resolver
            
            records = dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
            dkim_record = str(records[0]).strip('"')
            
            return {
                'found': True,
                'record': dkim_record,
                'passes': True
            }
        except Exception as e:
            logger.warning(f"DKIM check failed: {e}")
        
        return {'found': False, 'passes': False}


class EmailThreatDetector:
    """Detect threats in emails"""
    
    PHISHING_KEYWORDS = [
        'verify account', 'confirm identity', 'update payment',
        'urgent action', 'click here', 'limited time', 'expires',
        'validate', 'authenticate', 'suspicious activity',
        'unusual login', 'security alert', 'billing problem',
        'click link', 'confirm password', 'verify credentials'
    ]
    
    SPOOFING_INDICATORS = [
        'from != domain',  # Sender domain mismatch
        'dmarc_fail',
        'spf_fail',
        'dkim_fail'
    ]
    
    @staticmethod
    def detect_phishing(email_subject: str, email_body: str, email_html: str = None) -> Dict:
        """Detect phishing indicators"""
        threats = []
        phishing_score = 0
        
        text_content = email_body.lower()
        if email_html:
            soup = BeautifulSoup(email_html, 'html.parser')
            text_content += soup.get_text().lower()
        
        # Check for phishing keywords
        keyword_count = sum(1 for keyword in EmailThreatDetector.PHISHING_KEYWORDS 
                           if keyword in text_content)
        
        if keyword_count > 0:
            threats.append(f'Contains {keyword_count} phishing keywords')
            phishing_score += keyword_count * 15
        
        # Check for urgency indicators
        urgency_words = ['urgent', 'immediately', 'asap', 'now', 'today', 'limited time']
        urgency_count = sum(1 for word in urgency_words if word in text_content)
        
        if urgency_count >= 2:
            threats.append('High urgency pressure (common in phishing)')
            phishing_score += 20
        
        # Check for generic greetings (sign of spam/phishing)
        generic_greetings = ['dear user', 'dear customer', 'dear valued', 'hello there']
        if any(greeting in text_content for greeting in generic_greetings):
            threats.append('Generic greeting (not personalized)')
            phishing_score += 15
        
        # Check for suspicious links
        urls = EmailExtractor.extract_urls(email_body, email_html)
        if urls:
            for url_obj in urls:
                if 'click here' in url_obj.get('context', '').lower():
                    threats.append('Suspicious CTA with link')
                    phishing_score += 20
                    break
        
        return {
            'threats': threats,
            'phishing_probability': min(1.0, phishing_score / 100),
            'phishing_score': min(100, phishing_score)
        }
    
    @staticmethod
    def detect_spoofing(sender: str, domain: str, headers: Dict) -> Dict:
        """Detect sender spoofing"""
        threats = []
        spoofing_score = 0
        
        # Check if sender domain matches
        sender_domain = sender.split('@')[-1] if '@' in sender else ''
        
        if sender_domain != domain:
            threats.append('Sender domain mismatch')
            spoofing_score += 25
        
        # Check authentication records
        dmarc = EmailAuthChecker.check_dmarc(domain)
        spf = EmailAuthChecker.check_spf(domain)
        dkim = EmailAuthChecker.check_dkim(domain)
        
        if not dmarc['passes']:
            threats.append('DMARC check failed')
            spoofing_score += 20
        
        if not spf['passes']:
            threats.append('SPF check failed')
            spoofing_score += 20
        
        if not dkim['passes']:
            threats.append('DKIM check failed')
            spoofing_score += 20
        
        return {
            'threats': threats,
            'spoofing_score': spoofing_score,
            'authentication': {
                'dmarc': dmarc['passes'],
                'spf': spf['passes'],
                'dkim': dkim['passes']
            }
        }
    
    @staticmethod
    def detect_malicious_attachments(attachments: List[Dict]) -> Dict:
        """Detect potentially malicious attachments"""
        threats = []
        malware_score = 0
        
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.msi', '.com']
        dangerous_mimes = ['application/x-executable', 'application/x-msdownload']
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            mime_type = attachment.get('mime_type', '').lower()
            
            # Check extension
            if any(filename.endswith(ext) for ext in dangerous_extensions):
                threats.append(f'Executable attachment: {filename}')
                malware_score += 40
            
            # Check MIME type
            if any(mime in mime_type for mime in dangerous_mimes):
                threats.append(f'Dangerous MIME type: {mime_type}')
                malware_score += 40
            
            # Check for double extension tricks
            if '.' in filename[:-4]:
                parts = filename.split('.')
                if parts[-1] in ['exe', 'com', 'scr'] or parts[-2] in ['exe', 'com']:
                    threats.append(f'Double extension trick: {filename}')
                    malware_score += 30
        
        return {
            'threats': threats,
            'malware_score': malware_score,
            'safe': malware_score == 0
        }


class EmailAnalyzer:
    """Complete email analysis"""
    
    @staticmethod
    def full_analysis(email_data: Dict) -> Dict:
        """
        Complete email threat analysis
        
        Input: {
            'from': 'sender@domain.com',
            'subject': '...',
            'body': '...',
            'html': '...',
            'attachments': [...]
        }
        """
        
        sender = email_data.get('from', '')
        domain = sender.split('@')[-1] if '@' in sender else ''
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        html = email_data.get('html')
        attachments = email_data.get('attachments', [])
        
        # Extract components
        urls = EmailExtractor.extract_urls(body, html)
        qr_codes = EmailExtractor.extract_qr_codes(html, attachments)
        headers = EmailExtractor.extract_headers(email_data.get('headers', {}))
        
        # Detect threats
        phishing = EmailThreatDetector.detect_phishing(subject, body, html)
        spoofing = EmailThreatDetector.detect_spoofing(sender, domain, headers)
        malware = EmailThreatDetector.detect_malicious_attachments(attachments)
        
        # Combine threats
        all_threats = phishing['threats'] + spoofing['threats'] + malware['threats']
        
        # Calculate overall risk
        overall_score = (
            phishing['phishing_score'] * 0.4 +
            spoofing['spoofing_score'] * 0.3 +
            malware['malware_score'] * 0.3
        )
        
        return {
            'sender': sender,
            'domain': domain,
            'subject': subject,
            'extracted_urls': urls,
            'extracted_qr_codes': qr_codes,
            'threats': all_threats,
            'threat_count': len(all_threats),
            'risk_score': min(100, int(overall_score)),
            'phishing_analysis': phishing,
            'spoofing_analysis': spoofing,
            'malware_analysis': malware,
            'authentication': spoofing.get('authentication', {}),
            'dmarc_pass': spoofing.get('authentication', {}).get('dmarc', False),
            'spf_pass': spoofing.get('authentication', {}).get('spf', False),
            'dkim_pass': spoofing.get('authentication', {}).get('dkim', False),
        }
