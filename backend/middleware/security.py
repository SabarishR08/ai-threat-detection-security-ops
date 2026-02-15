# backend/middleware/security.py
"""
Security middleware for Flask application
Adds security headers and request validation
"""
import logging
from flask import request, jsonify
from functools import wraps

logger = logging.getLogger(__name__)


def add_security_headers(response):
    """
    Add security headers to all HTTP responses
    Protection against XSS, clickjacking, and other common web vulnerabilities
    """
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # XSS Protection (legacy but still useful for older browsers)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy (strict)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' ws: wss:;"
    )
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = (
        "geolocation=(), microphone=(), camera=()"
    )
    
    # HSTS (HTTP Strict Transport Security) - only if using HTTPS
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response


def validate_url_input(url: str) -> tuple[bool, str]:
    """
    Validate URL input for security
    Returns (is_valid, error_message)
    """
    if not url:
        return False, "URL cannot be empty"
    
    if not isinstance(url, str):
        return False, "URL must be a string"
    
    # Length check
    if len(url) > 2048:
        return False, "URL exceeds maximum length (2048 characters)"
    
    # Protocol check
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"
    
    # Null byte check (URL encoding attacks)
    if '\x00' in url or '%00' in url:
        return False, "URL contains invalid null bytes"
    
    # Control character check
    if any(ord(c) < 32 for c in url if c not in '\t\n\r'):
        return False, "URL contains invalid control characters"
    
    # JavaScript protocol check (XSS prevention)
    url_lower = url.lower()
    dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
    if any(url_lower.startswith(proto) for proto in dangerous_protocols):
        return False, "URL contains dangerous protocol"
    
    return True, ""


def validate_json_input(max_size: int = 1024 * 1024):  # 1MB default
    """
    Decorator to validate JSON input size and structure
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'PATCH']:
                # Check Content-Length header
                content_length = request.content_length
                if content_length and content_length > max_size:
                    logger.warning(f"Rejected oversized request: {content_length} bytes from {request.remote_addr}")
                    return jsonify({"error": "Request too large"}), 413
                
                # Validate JSON parsing
                try:
                    data = request.get_json(force=False, silent=False)
                    if data is None and request.data:
                        return jsonify({"error": "Invalid JSON"}), 400
                except Exception as e:
                    logger.warning(f"JSON parse error from {request.remote_addr}: {e}")
                    return jsonify({"error": "Malformed JSON"}), 400
            
            return f(*args, **kwargs)
        return wrapped
    return decorator


def sanitize_input(text: str, max_length: int = 10000) -> str:
    """Sanitize text input by removing dangerous characters"""
    if not text:
        return ""
    
    # Truncate
    text = str(text)[:max_length]
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Remove other control chars except newline, tab, carriage return
    text = ''.join(c for c in text if ord(c) >= 32 or c in '\t\n\r')
    
    return text.strip()


def rate_limit_exceeded_handler(e):
    """Custom handler for rate limit exceeded"""
    logger.warning(f"Rate limit exceeded from {request.remote_addr} on {request.path}")
    return jsonify({
        "error": "Rate limit exceeded",
        "message": str(e.description),
        "retry_after": "Please try again later"
    }), 429


def request_logger_middleware():
    """Log all incoming requests for security monitoring"""
    logger.info(
        f"{request.method} {request.path} "
        f"from {request.remote_addr} "
        f"UA: {request.headers.get('User-Agent', 'Unknown')[:100]}"
    )
