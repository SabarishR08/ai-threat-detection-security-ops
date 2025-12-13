"""
Unified Risk Scoring Engine (0-100 scale)

Generates comprehensive risk scores for all threat types
"""

import logging
from typing import Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """Calculate unified risk scores (0-100)"""
    
    # Risk categories with weights
    RISK_CATEGORIES = {
        'payload_type': 0.15,      # 15% - What kind of payload
        'threat_indicators': 0.25,  # 25% - Detected threats
        'reputation': 0.20,         # 20% - Source reputation
        'behavior': 0.15,          # 15% - Suspicious behavior
        'ai_confidence': 0.25      # 25% - AI analysis
    }
    
    @staticmethod
    def calculate_qr_risk_score(analysis_data: Dict) -> int:
        """
        Calculate QR code risk score (0-100)
        
        Input: Complete QR analysis data
        Output: Risk score 0-100
        """
        scores = {}
        
        # 1. Payload Type Risk (15%)
        payload_type = analysis_data.get('payload_type', 'unknown')
        payload_risk = RiskScoringEngine._score_payload_type(payload_type)
        scores['payload_type'] = payload_risk
        
        # 2. Threat Indicators (25%)
        threats = analysis_data.get('threats', [])
        threat_score = RiskScoringEngine._score_threats(threats)
        scores['threat_indicators'] = threat_score
        
        # 3. Reputation (20%)
        reputation = analysis_data.get('reputation', {})
        reputation_score = RiskScoringEngine._score_reputation(reputation)
        scores['reputation'] = reputation_score
        
        # 4. Behavioral Factors (15%)
        behavior_score = RiskScoringEngine._score_behavior(analysis_data)
        scores['behavior'] = behavior_score
        
        # 5. AI Confidence (25%)
        ai_score = RiskScoringEngine._score_ai_analysis(analysis_data)
        scores['ai_confidence'] = ai_score
        
        # Calculate weighted total
        total_score = sum(
            scores[category] * RiskScoringEngine.RISK_CATEGORIES[category]
            for category in scores
        )
        
        return min(100, max(0, int(total_score)))
    
    @staticmethod
    def calculate_url_risk_score(url_analysis: Dict) -> int:
        """Calculate URL risk score"""
        scores = {}
        
        # URL-specific scoring
        components = url_analysis.get('components', {})
        threats = url_analysis.get('threats', [])
        
        # Domain age factor
        domain_score = RiskScoringEngine._score_domain_age(url_analysis)
        scores['domain_age'] = domain_score
        
        # Redirect chain factor
        has_redirects = url_analysis.get('has_redirects', False)
        redirect_score = 30 if has_redirects else 0
        scores['redirects'] = redirect_score
        
        # Threat indicators
        threat_score = RiskScoringEngine._score_threats(threats)
        scores['threats'] = threat_score
        
        # Reputation
        reputation = url_analysis.get('reputation', {})
        reputation_score = RiskScoringEngine._score_reputation(reputation)
        scores['reputation'] = reputation_score
        
        # Calculate weighted total
        weights = {
            'domain_age': 0.25,
            'redirects': 0.20,
            'threats': 0.35,
            'reputation': 0.20
        }
        
        total_score = sum(
            scores[category] * weights.get(category, 0)
            for category in scores
        )
        
        return min(100, max(0, int(total_score)))
    
    @staticmethod
    def calculate_email_risk_score(email_analysis: Dict) -> int:
        """Calculate email risk score"""
        scores = {}
        
        # DMARC/SPF/DKIM
        dmarc_pass = email_analysis.get('dmarc_pass', False)
        spf_pass = email_analysis.get('spf_pass', False)
        dkim_pass = email_analysis.get('dkim_pass', False)
        
        auth_score = 0
        if not dmarc_pass:
            auth_score += 20
        if not spf_pass:
            auth_score += 20
        if not dkim_pass:
            auth_score += 20
        
        scores['authentication'] = min(60, auth_score)
        
        # URL threats in email
        urls = email_analysis.get('extracted_urls', [])
        if urls:
            # Score based on number of suspicious URLs
            suspicious_count = sum(1 for url in urls if 'risk_score' in url and url['risk_score'] > 50)
            url_score = min(40, suspicious_count * 10)
        else:
            url_score = 0
        
        scores['urls'] = url_score
        
        # Attachment threats
        attachments = email_analysis.get('attachments', [])
        attachment_score = len([a for a in attachments if not a.get('safe', True)]) * 15
        scores['attachments'] = min(40, attachment_score)
        
        # Phishing indicators
        phishing_score = email_analysis.get('phishing_probability', 0) * 100
        scores['phishing'] = phishing_score
        
        # Calculate weighted total
        weights = {
            'authentication': 0.20,
            'urls': 0.30,
            'attachments': 0.25,
            'phishing': 0.25
        }
        
        total_score = sum(
            scores[category] * weights.get(category, 0)
            for category in scores
        )
        
        return min(100, max(0, int(total_score)))
    
    @staticmethod
    def _score_payload_type(payload_type: str) -> int:
        """Score payload type risk"""
        payload_risks = {
            'url': 10,
            'text': 5,
            'email': 15,
            'tel': 15,
            'sms': 20,
            'wifi': 25,
            'crypto': 15,
            'upi': 20,
            'app_deeplink': 30,
            'base64': 35,
            'hex': 35,
            'vcard': 10,
            'mecard': 10,
            'icalendar': 10,
            'geolocation': 10,
            'otp': 15,
        }
        
        return payload_risks.get(payload_type, 20)
    
    @staticmethod
    def _score_threats(threats: List[str]) -> int:
        """Score based on number and severity of threats"""
        if not threats:
            return 0
        
        threat_severities = {
            'Malicious': 30,
            'Phishing': 30,
            'Spam': 15,
            'Suspicious': 20,
            'Warning': 10,
            'Info': 5,
        }
        
        total_score = 0
        for threat in threats:
            for severity, score in threat_severities.items():
                if severity.lower() in threat.lower():
                    total_score += score
                    break
            else:
                total_score += 15  # Default threat score
        
        return min(100, total_score)
    
    @staticmethod
    def _score_reputation(reputation: Dict) -> int:
        """Score based on reputation sources"""
        if not reputation:
            return 0
        
        is_reputable = reputation.get('reputable', True)
        sources = reputation.get('sources', {})
        
        if is_reputable:
            return 0
        
        # Deduct points for each bad source
        suspicious_sources = sum(1 for v in sources.values() if v == 'suspicious')
        return min(100, suspicious_sources * 25)
    
    @staticmethod
    def _score_behavior(analysis_data: Dict) -> int:
        """Score suspicious behavior"""
        score = 0
        
        # Check for redirect chains
        if analysis_data.get('has_redirects', False):
            redirect_chain = analysis_data.get('redirect_chain', [])
            if len(redirect_chain) > 2:
                score += 20
        
        # Check for encoded content
        if analysis_data.get('has_encoded_content', False):
            score += 15
        
        # Check for hidden content
        if analysis_data.get('has_hidden_content', False):
            score += 25
        
        return min(100, score)
    
    @staticmethod
    def _score_ai_analysis(analysis_data: Dict) -> int:
        """Score AI analysis results"""
        ai_results = analysis_data.get('ai_analysis', {})
        
        if not ai_results:
            return 50  # Neutral if no AI analysis
        
        # Use AI confidence scores
        phishing_prob = ai_results.get('phishing_probability', 0)
        scam_prob = ai_results.get('scam_probability', 0)
        malware_prob = ai_results.get('malware_probability', 0)
        
        return max(
            int(phishing_prob * 100),
            int(scam_prob * 100),
            int(malware_prob * 100)
        )
    
    @staticmethod
    def _score_domain_age(url_analysis: Dict) -> int:
        """Score domain age"""
        # This would be populated from WHOIS lookup
        domain_age_days = url_analysis.get('domain_age_days', 365)
        
        if domain_age_days < 30:
            return 80  # Very new domain
        elif domain_age_days < 365:
            return 50  # Young domain
        elif domain_age_days > 365 * 5:
            return 10  # Established domain
        else:
            return 30  # Mid-age domain
    
    @staticmethod
    def get_risk_level(risk_score: int) -> str:
        """Convert score to risk level"""
        if risk_score >= 80:
            return 'Critical'
        elif risk_score >= 60:
            return 'High'
        elif risk_score >= 40:
            return 'Medium'
        elif risk_score >= 20:
            return 'Low'
        else:
            return 'Safe'
    
    @staticmethod
    def get_risk_color(risk_score: int) -> str:
        """Get color for risk score"""
        level = RiskScoringEngine.get_risk_level(risk_score)
        colors = {
            'Safe': '#39ff14',      # Green
            'Low': '#87ceeb',       # Blue
            'Medium': '#ffb800',    # Orange
            'High': '#ff6b6b',      # Red
            'Critical': '#8b0000',  # Dark red
        }
        return colors.get(level, '#666666')
    
    @staticmethod
    def get_recommendation(risk_score: int) -> str:
        """Get user recommendation based on risk"""
        level = RiskScoringEngine.get_risk_level(risk_score)
        
        recommendations = {
            'Safe': 'Safe to use. No threats detected.',
            'Low': 'Generally safe. Minor concerns detected.',
            'Medium': 'Use caution. Verify before proceeding.',
            'High': 'Highly suspicious. Do not use.',
            'Critical': 'Malicious content confirmed. Block immediately.'
        }
        
        return recommendations.get(level, 'Unknown risk level')
    
    @staticmethod
    def generate_risk_report(
        threat_type: str,
        risk_score: int,
        threats: List[str],
        timestamp: str = None
    ) -> Dict:
        """Generate complete risk report"""
        
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        level = RiskScoringEngine.get_risk_level(risk_score)
        color = RiskScoringEngine.get_risk_color(risk_score)
        recommendation = RiskScoringEngine.get_recommendation(risk_score)
        
        return {
            'threat_type': threat_type,
            'risk_score': risk_score,
            'risk_level': level,
            'risk_color': color,
            'threats': threats,
            'threat_count': len(threats),
            'recommendation': recommendation,
            'timestamp': timestamp,
            'percentage': f"{risk_score}%"
        }
