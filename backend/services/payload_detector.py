"""
Advanced Payload Type Detection & Analysis Service

Detects: Base64, Hex, WiFi, Email, SMS, Tel, Crypto, UPI, vCard, Calendar, 
         Geolocation, App deeplinks, and more
"""

import re
import json
import base64
import binascii
from urllib.parse import unquote, parse_qs, urlparse
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class PayloadDetector:
    """Detect and analyze various QR payload types"""
    
    # Payload type definitions
    PAYLOAD_TYPES = {
        'url': 'Web URL',
        'base64': 'Base64 Encoded Data',
        'hex': 'Hexadecimal Encoded Data',
        'wifi': 'WiFi Auto-Connect',
        'email': 'Email Address (mailto)',
        'sms': 'SMS Message',
        'tel': 'Phone Call',
        'crypto': 'Cryptocurrency Wallet',
        'upi': 'UPI Payment',
        'vcard': 'Contact Card',
        'mecard': 'Mobile Contact Card',
        'icalendar': 'Calendar Event',
        'geolocation': 'GPS Coordinates',
        'app_deeplink': 'App Deep Link',
        'bitcoin': 'Bitcoin Address',
        'ethereum': 'Ethereum Address',
        'otp': 'One-Time Password',
        'text': 'Plain Text',
    }
    
    @staticmethod
    def detect_payload_type(data: str) -> dict:
        """
        Detect the type of payload in QR code
        
        Returns:
            {
                'type': 'type_name',
                'confidence': 0.0-1.0,
                'parsed': {...},
                'details': 'description'
            }
        """
        if not data or not isinstance(data, str):
            return {'type': 'unknown', 'confidence': 0.0}
        
        data = data.strip()
        
        # Try each detector in order of specificity
        detectors = [
            ('wifi', PayloadDetector._detect_wifi),
            ('email', PayloadDetector._detect_email),
            ('sms', PayloadDetector._detect_sms),
            ('tel', PayloadDetector._detect_tel),
            ('upi', PayloadDetector._detect_upi),
            ('crypto', PayloadDetector._detect_crypto),
            ('vcard', PayloadDetector._detect_vcard),
            ('mecard', PayloadDetector._detect_mecard),
            ('icalendar', PayloadDetector._detect_icalendar),
            ('geolocation', PayloadDetector._detect_geolocation),
            ('app_deeplink', PayloadDetector._detect_app_deeplink),
            ('otp', PayloadDetector._detect_otp),
            ('base64', PayloadDetector._detect_base64),
            ('hex', PayloadDetector._detect_hex),
            ('url', PayloadDetector._detect_url),
            ('text', PayloadDetector._detect_text),
        ]
        
        for type_name, detector_func in detectors:
            result = detector_func(data)
            if result and result.get('confidence', 0) > 0.5:
                return result
        
        # Default to text
        return {
            'type': 'text',
            'confidence': 0.3,
            'parsed': {'content': data},
            'details': 'Plain text content'
        }
    
    @staticmethod
    def _detect_wifi(data: str) -> dict:
        """Detect WiFi QR (WIFI:T:security;S:ssid;P:password;;)"""
        if not data.startswith('WIFI:'):
            return None
        
        try:
            parts = {}
            # Parse WIFI:T:WPA;S:MyNetwork;P:password;;
            tokens = data[5:].split(';')
            
            for token in tokens:
                if ':' in token:
                    key, value = token.split(':', 1)
                    if key == 'T':
                        parts['security'] = value
                    elif key == 'S':
                        parts['ssid'] = value
                    elif key == 'P':
                        parts['password'] = value
            
            if 'ssid' in parts:
                return {
                    'type': 'wifi',
                    'confidence': 0.95,
                    'parsed': parts,
                    'details': f"WiFi: {parts.get('ssid')} ({parts.get('security', 'Unknown')})"
                }
        except Exception as e:
            logger.debug(f"WiFi detection error: {e}")
        
        return None
    
    @staticmethod
    def _detect_email(data: str) -> dict:
        """Detect email (mailto:address@domain.com)"""
        if data.startswith('mailto:'):
            email = data[7:]
            # Parse mailto:addr@example.com?subject=X&body=Y
            if '?' in email:
                email_addr, params = email.split('?', 1)
                params_dict = parse_qs(params)
            else:
                email_addr = email
                params_dict = {}
            
            if '@' in email_addr and '.' in email_addr:
                return {
                    'type': 'email',
                    'confidence': 0.98,
                    'parsed': {
                        'email': email_addr,
                        'subject': params_dict.get('subject', [''])[0],
                        'body': params_dict.get('body', [''])[0]
                    },
                    'details': f"Email: {email_addr}"
                }
        
        return None
    
    @staticmethod
    def _detect_sms(data: str) -> dict:
        """Detect SMS (sms:+1234567890?body=message)"""
        if data.startswith('sms:'):
            phone_part = data[4:]
            if '?' in phone_part:
                phone, params = phone_part.split('?', 1)
                params_dict = parse_qs(params)
            else:
                phone = phone_part
                params_dict = {}
            
            if phone and re.match(r'^\+?[\d\s\-()]+$', phone):
                return {
                    'type': 'sms',
                    'confidence': 0.98,
                    'parsed': {
                        'phone': phone,
                        'message': params_dict.get('body', [''])[0]
                    },
                    'details': f"SMS: {phone}"
                }
        
        return None
    
    @staticmethod
    def _detect_tel(data: str) -> dict:
        """Detect phone (tel:+1234567890)"""
        if data.startswith('tel:'):
            phone = data[4:]
            if re.match(r'^\+?[\d\s\-()]+$', phone):
                return {
                    'type': 'tel',
                    'confidence': 0.98,
                    'parsed': {'phone': phone},
                    'details': f"Phone: {phone}"
                }
        
        return None
    
    @staticmethod
    def _detect_upi(data: str) -> dict:
        """Detect UPI (upi://pay?pa=user@bank&am=amount)"""
        if data.startswith('upi://'):
            try:
                params_str = data[6:]
                params = parse_qs(params_str)
                
                upi_id = params.get('pa', [''])[0]
                amount = params.get('am', [''])[0]
                description = params.get('tn', [''])[0]
                
                if upi_id and '@' in upi_id:
                    return {
                        'type': 'upi',
                        'confidence': 0.98,
                        'parsed': {
                            'upi_id': upi_id,
                            'amount': amount,
                            'description': description
                        },
                        'details': f"UPI: {upi_id} ({amount})"
                    }
            except Exception as e:
                logger.debug(f"UPI detection error: {e}")
        
        return None
    
    @staticmethod
    def _detect_crypto(data: str) -> dict:
        """Detect cryptocurrency wallets (Bitcoin, Ethereum, etc.)"""
        # Bitcoin: 1A1z7agoat1A1z7agoat (26-35 chars, starts with 1, 3, or bc1)
        # Ethereum: 0x + 40 hex chars
        
        if data.startswith('0x') and len(data) == 42:
            # Ethereum address
            if re.match(r'^0x[a-fA-F0-9]{40}$', data):
                return {
                    'type': 'crypto',
                    'confidence': 0.98,
                    'parsed': {'wallet_type': 'ethereum', 'address': data},
                    'details': f"Ethereum: {data[:10]}...{data[-6:]}"
                }
        
        # Bitcoin address patterns
        bitcoin_patterns = [
            r'^1[a-km-zA-HJ-NP-Z1-9]{25,34}$',  # P2PKH
            r'^3[a-km-zA-HJ-NP-Z1-9]{25,34}$',  # P2SH
            r'^bc1[a-z0-9]{39,59}$',             # Segwit
        ]
        
        for pattern in bitcoin_patterns:
            if re.match(pattern, data):
                return {
                    'type': 'crypto',
                    'confidence': 0.98,
                    'parsed': {'wallet_type': 'bitcoin', 'address': data},
                    'details': f"Bitcoin: {data[:10]}...{data[-6:]}"
                }
        
        return None
    
    @staticmethod
    def _detect_vcard(data: str) -> dict:
        """Detect vCard format (contact card)"""
        if 'BEGIN:VCARD' in data and 'END:VCARD' in data:
            contact = {}
            
            # Parse vCard fields
            for line in data.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.split(';')[0]  # Remove attributes
                    
                    if key == 'FN':
                        contact['name'] = value.strip()
                    elif key == 'TEL':
                        contact['phone'] = value.strip()
                    elif key == 'EMAIL':
                        contact['email'] = value.strip()
                    elif key == 'ORG':
                        contact['organization'] = value.strip()
            
            if contact.get('name'):
                return {
                    'type': 'vcard',
                    'confidence': 0.98,
                    'parsed': contact,
                    'details': f"Contact: {contact.get('name')}"
                }
        
        return None
    
    @staticmethod
    def _detect_mecard(data: str) -> dict:
        """Detect MECard format (mobile contact)"""
        if data.startswith('MECARD:'):
            contact = {}
            
            # Parse MECARD:N:John;TEL:1234567890;EMAIL:john@example.com;;
            fields = data[7:].split(';')
            
            for field in fields:
                if ':' in field:
                    key, value = field.split(':', 1)
                    if key == 'N':
                        contact['name'] = value
                    elif key == 'TEL':
                        contact['phone'] = value
                    elif key == 'EMAIL':
                        contact['email'] = value
                    elif key == 'ORG':
                        contact['organization'] = value
            
            if contact.get('name'):
                return {
                    'type': 'mecard',
                    'confidence': 0.98,
                    'parsed': contact,
                    'details': f"Contact: {contact.get('name')}"
                }
        
        return None
    
    @staticmethod
    def _detect_icalendar(data: str) -> dict:
        """Detect iCalendar event"""
        if 'BEGIN:VEVENT' in data and 'END:VEVENT' in data:
            event = {}
            
            for line in data.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.split(';')[0]
                    
                    if key == 'SUMMARY':
                        event['title'] = value.strip()
                    elif key == 'DTSTART':
                        event['start'] = value.strip()
                    elif key == 'DTEND':
                        event['end'] = value.strip()
                    elif key == 'LOCATION':
                        event['location'] = value.strip()
            
            if event.get('title'):
                return {
                    'type': 'icalendar',
                    'confidence': 0.98,
                    'parsed': event,
                    'details': f"Event: {event.get('title')}"
                }
        
        return None
    
    @staticmethod
    def _detect_geolocation(data: str) -> dict:
        """Detect geo location (geo:latitude,longitude)"""
        if data.startswith('geo:'):
            geo_part = data[4:]
            
            # Match geo:latitude,longitude[,altitude]
            match = re.match(r'^([-\d.]+),([-\d.]+)(?:,([-\d.]+))?', geo_part)
            
            if match:
                return {
                    'type': 'geolocation',
                    'confidence': 0.98,
                    'parsed': {
                        'latitude': match.group(1),
                        'longitude': match.group(2),
                        'altitude': match.group(3) or None
                    },
                    'details': f"Location: {match.group(1)}, {match.group(2)}"
                }
        
        return None
    
    @staticmethod
    def _detect_app_deeplink(data: str) -> dict:
        """Detect app deep links (intent://, whatsapp://, etc.)"""
        app_schemes = ['intent://', 'whatsapp://', 'viber://', 'telegram://', 
                       'skype://', 'slack://', 'discord://', 'tiktok://', 'instagram://']
        
        for scheme in app_schemes:
            if data.startswith(scheme):
                app_name = scheme.replace('://', '')
                return {
                    'type': 'app_deeplink',
                    'confidence': 0.95,
                    'parsed': {
                        'app': app_name,
                        'uri': data
                    },
                    'details': f"App Link: {app_name}"
                }
        
        return None
    
    @staticmethod
    def _detect_otp(data: str) -> dict:
        """Detect OTP auto-fill (otpauth://)"""
        if data.startswith('otpauth://'):
            try:
                params = parse_qs(urlparse(data).query)
                issuer = params.get('issuer', ['Unknown'])[0]
                account = params.get('accountname', ['Unknown'])[0]
                
                return {
                    'type': 'otp',
                    'confidence': 0.98,
                    'parsed': {
                        'issuer': issuer,
                        'account': account
                    },
                    'details': f"OTP: {issuer} ({account})"
                }
            except Exception as e:
                logger.debug(f"OTP detection error: {e}")
        
        return None
    
    @staticmethod
    def _detect_base64(data: str) -> dict:
        """Detect Base64 encoded data"""
        # Base64 regex pattern
        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', data) or len(data) % 4 != 0:
            return None
        
        # Length check - must be significant
        if len(data) < 12:
            return None
        
        try:
            decoded = base64.b64decode(data, validate=True)
            
            # Try to detect decoded content type
            content_type = 'binary'
            try:
                decoded_str = decoded.decode('utf-8')
                content_type = 'text'
            except:
                if decoded.startswith(b'\x89PNG'):
                    content_type = 'PNG image'
                elif decoded.startswith(b'\xff\xd8\xff'):
                    content_type = 'JPEG image'
                elif decoded.startswith(b'%PDF'):
                    content_type = 'PDF document'
            
            return {
                'type': 'base64',
                'confidence': 0.90,
                'parsed': {
                    'decoded_type': content_type,
                    'size': len(decoded),
                    'decoded_preview': decoded_str[:100] if content_type == 'text' else '[binary data]'
                },
                'details': f"Base64: {content_type} ({len(decoded)} bytes)"
            }
        except Exception as e:
            logger.debug(f"Base64 detection error: {e}")
        
        return None
    
    @staticmethod
    def _detect_hex(data: str) -> dict:
        """Detect hexadecimal encoded data"""
        if not re.match(r'^[0-9a-fA-F]+$', data):
            return None
        
        # Must have even length
        if len(data) % 2 != 0:
            return None
        
        # Length check
        if len(data) < 12:
            return None
        
        try:
            decoded = bytes.fromhex(data)
            
            content_type = 'binary'
            try:
                decoded_str = decoded.decode('utf-8')
                content_type = 'text'
            except:
                pass
            
            return {
                'type': 'hex',
                'confidence': 0.85,
                'parsed': {
                    'decoded_type': content_type,
                    'size': len(decoded)
                },
                'details': f"Hexadecimal: {content_type} ({len(decoded)} bytes)"
            }
        except Exception as e:
            logger.debug(f"Hex detection error: {e}")
        
        return None
    
    @staticmethod
    def _detect_url(data: str) -> dict:
        """Detect URL"""
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        
        if re.match(url_pattern, data, re.IGNORECASE):
            return {
                'type': 'url',
                'confidence': 0.98,
                'parsed': {'url': data},
                'details': f"URL: {data[:50]}..."
            }
        
        return None
    
    @staticmethod
    def _detect_text(data: str) -> dict:
        """Fallback to plain text"""
        return {
            'type': 'text',
            'confidence': 0.2,
            'parsed': {'content': data[:200]},
            'details': 'Plain text'
        }


class PayloadValidator:
    """Validate and analyze payload safety"""
    
    # Suspicious patterns
    SUSPICIOUS_KEYWORDS = [
        'verify', 'confirm', 'urgent', 'action required', 'expire',
        'update account', 'reset password', 'validate', 'authentication',
        'suspicious activity', 'unusual login', 'limited time', 'claim',
        'congratulations', 'winner', 'refund', 'tax', 'invoice',
        'payment due', 'billing', 'confirm identity', 'security alert'
    ]
    
    PHISHING_DOMAINS = [
        'bit.ly', 'tinyurl', 'short.link',  # URL shorteners
    ]
    
    @staticmethod
    def validate_payload(payload_type: str, parsed_data: dict) -> dict:
        """
        Validate payload for threats
        
        Returns:
            {
                'is_safe': bool,
                'risk_level': 'low' | 'medium' | 'high',
                'threats': [list of detected threats],
                'score': 0-100
            }
        """
        threats = []
        risk_score = 0
        
        # Type-specific validation
        if payload_type == 'url':
            threats, risk_score = PayloadValidator._validate_url(parsed_data.get('url', ''))
        
        elif payload_type in ['email', 'sms', 'tel']:
            threats, risk_score = PayloadValidator._validate_contact(parsed_data)
        
        elif payload_type == 'wifi':
            threats, risk_score = PayloadValidator._validate_wifi(parsed_data)
        
        elif payload_type == 'crypto':
            threats, risk_score = PayloadValidator._validate_crypto(parsed_data)
        
        elif payload_type == 'base64':
            threats, risk_score = PayloadValidator._validate_base64(parsed_data)
        
        elif payload_type in ['vcard', 'mecard']:
            threats, risk_score = PayloadValidator._validate_contact_card(parsed_data)
        
        return {
            'is_safe': risk_score < 40,
            'risk_level': 'low' if risk_score < 33 else 'medium' if risk_score < 66 else 'high',
            'threats': threats,
            'risk_score': risk_score
        }
    
    @staticmethod
    def _validate_url(url: str) -> tuple:
        """Validate URL for threats"""
        threats = []
        risk_score = 0
        
        # Check for suspicious patterns
        if any(keyword in url.lower() for keyword in PayloadValidator.SUSPICIOUS_KEYWORDS):
            threats.append('Contains phishing keywords')
            risk_score += 20
        
        # Check for URL shorteners
        if any(domain in url.lower() for domain in PayloadValidator.PHISHING_DOMAINS):
            threats.append('Uses URL shortener (hidden destination)')
            risk_score += 25
        
        # Check for IP-based URLs
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            threats.append('IP-based URL (suspicious)')
            risk_score += 30
        
        # Check for encoded content
        if '%' in url:
            threats.append('Contains URL-encoded content')
            risk_score += 10
        
        # Check for long URLs
        if len(url) > 100:
            threats.append('Unusually long URL')
            risk_score += 5
        
        return threats, risk_score
    
    @staticmethod
    def _validate_contact(data: dict) -> tuple:
        """Validate contact info for threats"""
        threats = []
        risk_score = 0
        
        # Check message for suspicious content
        message = data.get('message', '') or data.get('body', '')
        if message:
            if any(keyword in message.lower() for keyword in PayloadValidator.SUSPICIOUS_KEYWORDS):
                threats.append('Suspicious message content')
                risk_score += 25
            
            # Check for URLs in message
            if re.search(r'https?://', message):
                threats.append('Message contains hidden URL')
                risk_score += 20
        
        return threats, risk_score
    
    @staticmethod
    def _validate_wifi(data: dict) -> tuple:
        """Validate WiFi payload"""
        threats = []
        risk_score = 0
        
        ssid = data.get('ssid', '').lower()
        
        # Check SSID for impersonation
        legitimate_ssids = ['starbucks', 'airport', 'hotel', 'library', 'cafe']
        generic_ssids = ['free wifi', 'public wifi', 'wifi', 'network']
        
        if any(legitimate in ssid for legitimate in legitimate_ssids):
            if 'fake' in ssid or 'phishing' in ssid:
                threats.append('Impersonates legitimate WiFi network')
                risk_score += 35
        
        if any(generic in ssid for generic in generic_ssids):
            threats.append('Generic suspicious WiFi SSID')
            risk_score += 20
        
        return threats, risk_score
    
    @staticmethod
    def _validate_crypto(data: dict) -> tuple:
        """Validate cryptocurrency wallet"""
        threats = []
        risk_score = 0
        
        # Crypto addresses are generally safe to scan, but may indicate scam
        threats.append('Cryptocurrency payment request - verify legitimacy')
        risk_score = 15
        
        return threats, risk_score
    
    @staticmethod
    def _validate_base64(data: dict) -> tuple:
        """Validate base64 payload"""
        threats = []
        risk_score = 0
        
        decoded_type = data.get('decoded_type', '')
        
        if decoded_type == 'text':
            # Could contain hidden URLs or commands
            preview = data.get('decoded_preview', '')
            if 'http' in preview.lower():
                threats.append('Base64 contains hidden URL')
                risk_score += 25
        
        elif decoded_type in ['PDF document']:
            threats.append('Base64 encoded document - verify source')
            risk_score += 20
        
        else:
            threats.append('Base64 contains unknown binary data')
            risk_score += 30
        
        return threats, risk_score
    
    @staticmethod
    def _validate_contact_card(data: dict) -> tuple:
        """Validate contact card"""
        threats = []
        risk_score = 0
        
        # Check for suspicious fields
        email = data.get('email', '')
        if email and 'phishing' in email.lower():
            threats.append('Suspicious email in contact card')
            risk_score += 30
        
        return threats, risk_score
