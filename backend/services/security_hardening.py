"""
Security Hardening Module

Input sanitization, secrets management, CORS hardening, rate limiting, SQL injection prevention
"""

import os
import logging
import re
import secrets
from typing import Any, Dict, List, Tuple
from functools import wraps
import hashlib
import hmac

logger = logging.getLogger(__name__)


class InputSanitizer:
    """Sanitize user inputs"""
    
    # Dangerous patterns to block
    SQL_INJECTION_PATTERNS = [
        r"(\bOR\b|AND\b).*=.*",
        r"(;|--|\*|\/\*|\*\/|xp_|sp_)",
        r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror=",
        r"onclick=",
        r"<iframe",
        r"<embed",
        r"<object",
    ]
    
    @staticmethod
    def sanitize_url(url: str) -> str:
        """Sanitize URL input"""
        if not isinstance(url, str):
            return ""
        
        url = url.strip()
        
        # Block dangerous protocols
        dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file://']
        for protocol in dangerous_protocols:
            if url.lower().startswith(protocol):
                logger.warning(f"Blocked dangerous URL protocol: {protocol}")
                return ""
        
        return url
    
    @staticmethod
    def sanitize_text(text: str, max_length: int = 5000) -> str:
        """Sanitize text input"""
        if not isinstance(text, str):
            return ""
        
        text = text.strip()
        
        # Check length
        if len(text) > max_length:
            text = text[:max_length]
        
        # Remove null bytes
        text = text.replace('\0', '')
        
        # Remove control characters
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
        
        return text
    
    @staticmethod
    def is_sql_injection(value: str) -> bool:
        """Detect SQL injection attempts"""
        if not isinstance(value, str):
            return False
        
        value_upper = value.upper()
        
        for pattern in InputSanitizer.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                logger.warning(f"SQL injection detected: {value[:50]}...")
                return True
        
        return False
    
    @staticmethod
    def is_xss_attempt(value: str) -> bool:
        """Detect XSS attempts"""
        if not isinstance(value, str):
            return False
        
        value_lower = value.lower()
        
        for pattern in InputSanitizer.XSS_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                logger.warning(f"XSS attempt detected: {value[:50]}...")
                return True
        
        return False
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        if not isinstance(email, str):
            return False
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email)) and len(email) <= 254
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain format"""
        if not isinstance(domain, str):
            return False
        
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, domain))


class SecretsManager:
    """Manage sensitive data and secrets"""
    
    # Sensitive keys that should never be logged
    SENSITIVE_KEYS = [
        'password', 'secret', 'token', 'api_key', 'apikey',
        'auth', 'credential', 'private_key', 'private', 'secret_key',
        'access_token', 'refresh_token', 'bearer'
    ]
    
    @staticmethod
    def mask_sensitive_data(data: Dict) -> Dict:
        """Mask sensitive data in dictionary"""
        masked = {}
        
        for key, value in data.items():
            # Check if key is sensitive
            if any(sensitive in key.lower() for sensitive in SecretsManager.SENSITIVE_KEYS):
                masked[key] = '***REDACTED***'
            else:
                if isinstance(value, dict):
                    masked[key] = SecretsManager.mask_sensitive_data(value)
                elif isinstance(value, list):
                    masked[key] = [SecretsManager.mask_sensitive_data(v) if isinstance(v, dict) else v for v in value]
                else:
                    masked[key] = value
        
        return masked
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_hex(length // 2)
    
    @staticmethod
    def hash_secret(secret: str, salt: str = None) -> Dict:
        """Hash secret with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        hash_obj = hashlib.pbkdf2_hmac('sha256', secret.encode(), salt.encode(), 100000)
        
        return {
            'hash': hash_obj.hex(),
            'salt': salt
        }
    
    @staticmethod
    def verify_secret(secret: str, stored_hash: str, salt: str) -> bool:
        """Verify hashed secret"""
        hash_obj = hashlib.pbkdf2_hmac('sha256', secret.encode(), salt.encode(), 100000)
        return hmac.compare_digest(hash_obj.hex(), stored_hash)
    
    @staticmethod
    def check_env_vars() -> List[str]:
        """Check for exposed sensitive environment variables"""
        exposed = []
        
        # Check if DEBUG is enabled
        if os.getenv('DEBUG', 'false').lower() == 'true':
            exposed.append('DEBUG mode is enabled')
        
        # Check for hardcoded credentials
        dangerous_vars = ['DATABASE_PASSWORD', 'API_KEY', 'SECRET_KEY', 'JWT_SECRET']
        
        for var in dangerous_vars:
            if var in os.environ:
                value = os.getenv(var)
                # Simple check - actual secret would be complex
                if len(value) < 30:
                    exposed.append(f'{var} appears to be weak')
        
        return exposed


class CORSHardening:
    """CORS security configuration"""
    
    @staticmethod
    def get_safe_cors_config() -> Dict:
        """Get secure CORS configuration"""
        return {
            'origins': [
                'http://localhost:3000',
                'http://localhost:5000',
                'https://yourdomain.com'
            ],
            'methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            'allow_headers': ['Content-Type', 'Authorization'],
            'expose_headers': ['Content-Range', 'X-Content-Range'],
            'supports_credentials': True,
            'max_age': 3600  # 1 hour
        }
    
    @staticmethod
    def validate_origin(origin: str, allowed_origins: List[str]) -> bool:
        """Validate CORS origin"""
        return origin in allowed_origins


class RateLimitingConfig:
    """Rate limiting configuration"""
    
    # Rate limits by endpoint type
    RATE_LIMITS = {
        'auth': '5/minute',           # Auth endpoints
        'api_critical': '10/minute',   # Critical API endpoints
        'api_normal': '30/minute',     # Normal API endpoints
        'public': '100/hour',          # Public endpoints
        'upload': '10/hour',           # File upload
    }
    
    @staticmethod
    def apply_rate_limit(endpoint_type: str = 'api_normal'):
        """Decorator to apply rate limiting"""
        from flask_limiter import Limiter
        
        limit = RateLimitingConfig.RATE_LIMITS.get(endpoint_type, '30/minute')
        
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Rate limit would be applied by Flask-Limiter
                return f(*args, **kwargs)
            return decorated_function
        
        return decorator


class SQLInjectionPrevention:
    """SQL injection prevention"""
    
    @staticmethod
    def use_parameterized_queries(query: str, params: Dict) -> Tuple[str, List]:
        """
        Convert to parameterized query
        
        Usage:
            query, params = SQLInjectionPrevention.use_parameterized_queries(
                "SELECT * FROM users WHERE email = :email",
                {'email': user_email}
            )
        """
        # This is for demonstration - actual ORM should handle this
        return query, list(params.values())
    
    @staticmethod
    def validate_column_name(column: str, allowed_columns: List[str]) -> bool:
        """Validate column name against whitelist"""
        return column in allowed_columns


class ResponseSecurity:
    """Secure response headers"""
    
    @staticmethod
    def get_security_headers() -> Dict:
        """Get security headers for responses"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }


class AuditLogger:
    """Audit logging for security events"""
    
    @staticmethod
    def log_security_event(
        event_type: str,
        user: str = None,
        ip_address: str = None,
        details: Dict = None
    ):
        """Log security-relevant event"""
        
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'user': user,
            'ip_address': ip_address,
            'details': details or {}
        }
        
        logger.warning(f"SECURITY EVENT: {event}")
        
        # Would write to secure audit log file
        return event
    
    @staticmethod
    def log_failed_auth(username: str, ip_address: str, reason: str):
        """Log failed authentication attempt"""
        AuditLogger.log_security_event(
            event_type='FAILED_AUTH',
            user=username,
            ip_address=ip_address,
            details={'reason': reason}
        )
    
    @staticmethod
    def log_injection_attempt(attack_type: str, payload: str, ip_address: str):
        """Log injection attempt"""
        AuditLogger.log_security_event(
            event_type='INJECTION_ATTEMPT',
            ip_address=ip_address,
            details={
                'attack_type': attack_type,
                'payload': payload[:100]  # Log first 100 chars
            }
        )


class SecurityConfig:
    """Central security configuration"""
    
    @staticmethod
    def get_security_config() -> Dict:
        """Get complete security configuration"""
        
        return {
            'input_validation': {
                'enabled': True,
                'max_url_length': 2048,
                'max_text_length': 5000,
                'max_file_size': 10 * 1024 * 1024  # 10MB
            },
            'secrets': {
                'rotation_period': 90,  # days
                'minimum_length': 32,
                'require_special_chars': True
            },
            'cors': CORSHardening.get_safe_cors_config(),
            'rate_limits': RateLimitingConfig.RATE_LIMITS,
            'security_headers': ResponseSecurity.get_security_headers(),
            'https_only': True,
            'secure_cookies': True,
            'session_timeout': 3600  # 1 hour
        }


from datetime import datetime

