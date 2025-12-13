"""
Dashboard Enhancement - Risk scoring, visualizations, reports
"""

import json
from typing import Dict, List
from datetime import datetime, timedelta
from collections import Counter


class DashboardDataGenerator:
    """Generate dashboard data for visualizations"""
    
    @staticmethod
    def generate_threat_distribution(threat_logs: List[Dict]) -> Dict:
        """Generate threat distribution for pie chart"""
        
        categories = []
        for log in threat_logs:
            categories.append(log.get('category', 'unknown'))
        
        distribution = Counter(categories)
        
        return {
            'labels': list(distribution.keys()),
            'data': list(distribution.values()),
            'colors': [
                '#ff6b6b', '#4ecdc4', '#45b7d1', '#ffd93d',
                '#6bcf7f', '#ff85a2', '#a29bfe', '#f368e0'
            ]
        }
    
    @staticmethod
    def generate_severity_distribution(threat_logs: List[Dict]) -> Dict:
        """Generate severity distribution"""
        
        severities = {}
        for log in threat_logs:
            severity = log.get('severity', 'Low')
            severities[severity] = severities.get(severity, 0) + 1
        
        return {
            'High': severities.get('High', 0),
            'Medium': severities.get('Medium', 0),
            'Low': severities.get('Low', 0),
            'Unknown': severities.get('Unknown', 0)
        }
    
    @staticmethod
    def generate_timeline_data(threat_logs: List[Dict], days: int = 30) -> Dict:
        """Generate threat timeline for line chart"""
        
        now = datetime.now()
        timeline = {}
        
        for i in range(days, 0, -1):
            date = (now - timedelta(days=i)).strftime('%Y-%m-%d')
            timeline[date] = 0
        
        for log in threat_logs:
            timestamp = log.get('timestamp', '')
            if timestamp:
                date = timestamp.split('T')[0]  # Extract date part
                if date in timeline:
                    timeline[date] += 1
        
        return {
            'labels': list(timeline.keys()),
            'data': list(timeline.values())
        }
    
    @staticmethod
    def generate_top_threats(threat_logs: List[Dict], limit: int = 10) -> List[Dict]:
        """Generate top threats list"""
        
        url_counts = {}
        for log in threat_logs:
            url = log.get('url', 'unknown')
            if url not in url_counts:
                url_counts[url] = {
                    'count': 0,
                    'severity': log.get('severity', 'Low'),
                    'category': log.get('category', 'unknown'),
                    'last_seen': log.get('timestamp', '')
                }
            url_counts[url]['count'] += 1
        
        # Sort by count
        sorted_threats = sorted(
            url_counts.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:limit]
        
        return [
            {
                'url': url,
                **threat_info
            }
            for url, threat_info in sorted_threats
        ]
    
    @staticmethod
    def generate_risk_cards(threat_logs: List[Dict]) -> List[Dict]:
        """Generate risk score cards"""
        
        if not threat_logs:
            return []
        
        # Group by risk level
        critical_count = sum(1 for log in threat_logs if log.get('severity') == 'High')
        medium_count = sum(1 for log in threat_logs if log.get('severity') == 'Medium')
        low_count = sum(1 for log in threat_logs if log.get('severity') == 'Low')
        
        total_count = len(threat_logs)
        risk_score = (critical_count * 100 + medium_count * 50 + low_count * 10) / total_count if total_count > 0 else 0
        
        return [
            {
                'title': 'Critical Threats',
                'count': critical_count,
                'percentage': (critical_count / total_count * 100) if total_count > 0 else 0,
                'color': '#ff6b6b',
                'icon': 'alert-circle',
                'risk_level': 'Critical'
            },
            {
                'title': 'Medium Threats',
                'count': medium_count,
                'percentage': (medium_count / total_count * 100) if total_count > 0 else 0,
                'color': '#ffd93d',
                'icon': 'alert-triangle',
                'risk_level': 'Medium'
            },
            {
                'title': 'Low Threats',
                'count': low_count,
                'percentage': (low_count / total_count * 100) if total_count > 0 else 0,
                'color': '#4ecdc4',
                'icon': 'info',
                'risk_level': 'Low'
            },
            {
                'title': 'Overall Risk Score',
                'count': f'{int(risk_score)}/100',
                'percentage': risk_score,
                'color': '#45b7d1',
                'icon': 'shield',
                'risk_level': 'Critical' if risk_score > 70 else 'Medium' if risk_score > 40 else 'Low'
            }
        ]
    
    @staticmethod
    def generate_summary_stats(threat_logs: List[Dict]) -> Dict:
        """Generate summary statistics"""
        
        if not threat_logs:
            return {
                'total_threats': 0,
                'threats_today': 0,
                'threats_week': 0,
                'threats_month': 0,
                'average_daily': 0,
                'trend': 'stable'
            }
        
        now = datetime.now()
        today = now.strftime('%Y-%m-%d')
        week_ago = (now - timedelta(days=7)).strftime('%Y-%m-%d')
        month_ago = (now - timedelta(days=30)).strftime('%Y-%m-%d')
        
        today_count = sum(1 for log in threat_logs if log.get('timestamp', '').startswith(today))
        week_count = sum(1 for log in threat_logs if log.get('timestamp', '') >= week_ago)
        month_count = sum(1 for log in threat_logs if log.get('timestamp', '') >= month_ago)
        
        # Determine trend
        last_week_month = (now - timedelta(days=37)).strftime('%Y-%m-%d')
        prev_month = sum(1 for log in threat_logs if last_week_month <= log.get('timestamp', '') < month_ago)
        
        trend_direction = 'up' if month_count > prev_month else 'down' if month_count < prev_month else 'stable'
        
        return {
            'total_threats': len(threat_logs),
            'threats_today': today_count,
            'threats_week': week_count,
            'threats_month': month_count,
            'average_daily': month_count // 30 if month_count > 0 else 0,
            'trend': trend_direction,
            'trend_change': abs(month_count - prev_month) if prev_month > 0 else 0
        }


class ReportGenerator:
    """Generate threat reports"""
    
    @staticmethod
    def generate_html_report(threat_logs: List[Dict], title: str = "Threat Report") -> str:
        """Generate HTML report"""
        
        stats = DashboardDataGenerator.generate_summary_stats(threat_logs)
        cards = DashboardDataGenerator.generate_risk_cards(threat_logs)
        top_threats = DashboardDataGenerator.generate_top_threats(threat_logs)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{title}</title>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; }}
                .header {{ text-align: center; color: #333; }}
                .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
                .card {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
                .card h3 {{ margin: 0; color: #666; }}
                .card .value {{ font-size: 32px; font-weight: bold; color: #333; }}
                .threats-list {{ margin-top: 20px; }}
                .threat-item {{ background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #ff6b6b; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f5f5f5; font-weight: 600; }}
                tr:hover {{ background-color: #f9f9f9; }}
                .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
                .badge-high {{ background-color: #ff6b6b; color: white; }}
                .badge-medium {{ background-color: #ffd93d; color: #333; }}
                .badge-low {{ background-color: #4ecdc4; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{title}</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <div class="card">
                    <h3>Total Threats</h3>
                    <div class="value">{stats['total_threats']}</div>
                </div>
                <div class="card">
                    <h3>Today</h3>
                    <div class="value">{stats['threats_today']}</div>
                </div>
                <div class="card">
                    <h3>This Week</h3>
                    <div class="value">{stats['threats_week']}</div>
                </div>
                <div class="card">
                    <h3>This Month</h3>
                    <div class="value">{stats['threats_month']}</div>
                </div>
            </div>
            
            <div class="threats-list">
                <h2>Risk Summary</h2>
        """
        
        for card in cards:
            html += f"""
                <div class="threat-item">
                    <h4>{card['title']}</h4>
                    <p>Count: {card['count']} ({card['percentage']:.1f}%)</p>
                </div>
            """
        
        html += """
                <h2>Top Threats</h2>
                <table>
                    <thead>
                        <tr>
                            <th>URL/Content</th>
                            <th>Count</th>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for threat in top_threats:
            severity_class = f"badge-{threat['severity'].lower()}"
            html += f"""
                        <tr>
                            <td>{threat['url'][:50]}...</td>
                            <td>{threat['count']}</td>
                            <td><span class="badge {severity_class}">{threat['severity']}</span></td>
                            <td>{threat['category']}</td>
                            <td>{threat['last_seen']}</td>
                        </tr>
            """
        
        html += """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        
        return html
    
    @staticmethod
    def generate_json_report(threat_logs: List[Dict]) -> Dict:
        """Generate JSON report"""
        
        return {
            'generated_at': datetime.now().isoformat(),
            'summary': DashboardDataGenerator.generate_summary_stats(threat_logs),
            'risk_cards': DashboardDataGenerator.generate_risk_cards(threat_logs),
            'threat_distribution': DashboardDataGenerator.generate_threat_distribution(threat_logs),
            'severity_distribution': DashboardDataGenerator.generate_severity_distribution(threat_logs),
            'top_threats': DashboardDataGenerator.generate_top_threats(threat_logs),
            'timeline': DashboardDataGenerator.generate_timeline_data(threat_logs),
            'total_items': len(threat_logs)
        }


class ThemeManager:
    """Dark mode and theme management"""
    
    THEMES = {
        'light': {
            'primary': '#007bff',
            'danger': '#dc3545',
            'success': '#28a745',
            'warning': '#ffc107',
            'background': '#ffffff',
            'text': '#333333',
            'border': '#dee2e6',
        },
        'dark': {
            'primary': '#0d6efd',
            'danger': '#dc3545',
            'success': '#198754',
            'warning': '#ffc107',
            'background': '#1a1a1a',
            'text': '#e0e0e0',
            'border': '#404040',
        },
        'high-contrast': {
            'primary': '#0000ff',
            'danger': '#ff0000',
            'success': '#00cc00',
            'warning': '#ff6600',
            'background': '#000000',
            'text': '#ffffff',
            'border': '#ffffff',
        }
    }
    
    @staticmethod
    def get_theme_css(theme: str = 'light') -> str:
        """Get theme CSS"""
        colors = ThemeManager.THEMES.get(theme, ThemeManager.THEMES['light'])
        
        css = f"""
        :root {{
            --primary: {colors['primary']};
            --danger: {colors['danger']};
            --success: {colors['success']};
            --warning: {colors['warning']};
            --background: {colors['background']};
            --text: {colors['text']};
            --border: {colors['border']};
        }}
        
        body {{
            background-color: var(--background);
            color: var(--text);
        }}
        """
        
        return css
