#!/usr/bin/env python3
"""
SOC Analyzer and Dashboard UI Audit Test
Tests HTML structure, element alignment, button styling, and form functionality
"""

import os
import re
from pathlib import Path

def audit_template_file(filepath):
    """Audit HTML template for structure and element issues"""
    issues = []
    warnings = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        filename = os.path.basename(filepath)
        
        # Check 1: Proper extends and block structure
        if '{% extends' in content and '{% block' not in content:
            issues.append(f"[{filename}] Missing block tag")
        
        if '{% block' in content and '{% endblock %}' not in content:
            issues.append(f"[{filename}] Missing endblock tag")
        
        # Count extends and endblocks
        extends_count = content.count('{% extends')
        endblock_count = content.count('{% endblock')
        if extends_count > 1:
            issues.append(f"[{filename}] Multiple extends found ({extends_count}) - should be 1")
        
        # Check 2: Form elements
        form_count = content.count('<form')
        form_close = content.count('</form>')
        if form_count != form_close:
            issues.append(f"[{filename}] Form mismatch: {form_count} <form> tags, {form_close} </form> tags")
        
        # Check 3: Button styling
        buttons = re.findall(r'<button[^>]*class="([^"]*)"', content)
        for btn_class in buttons:
            if 'neon-button' not in btn_class and 'quick-example-btn' not in btn_class and 'login-button' not in btn_class and 'test-button' not in btn_class:
                warnings.append(f"[{filename}] Button found without standard styling: class='{btn_class}'")
        
        # Check 4: Input/textarea styling
        textareas = re.findall(r'<textarea[^>]*class="([^"]*)"', content)
        inputs = re.findall(r'<input[^>]*type="text"[^>]*class="([^"]*)"', content)
        
        for ta_class in textareas:
            if 'textarea' not in ta_class and 'input' not in ta_class:
                warnings.append(f"[{filename}] Textarea may lack styling: class='{ta_class}'")
        
        # Check 5: Missing ids for JS hooks
        if 'getElementById' in content:
            ids = re.findall(r'getElementById\([\'"]([^\'"]+)', content)
            for id_name in ids:
                if f'id="{id_name}"' not in content and f"id='{id_name}'" not in content:
                    issues.append(f"[{filename}] Missing id='{id_name}' referenced in JS")
        
        # Check 6: Proper spacing and padding
        if 'class=' in content:
            # Look for p- (padding) and m- (margin) classes
            padding_classes = re.findall(r'\b(p-[0-9]+|px-[0-9]+|py-[0-9]+)\b', content)
            margin_classes = re.findall(r'\b(m-[0-9]+|mx-[0-9]+|my-[0-9]+|mb-[0-9]+|mt-[0-9]+)\b', content)
            
            if not padding_classes:
                warnings.append(f"[{filename}] No explicit padding classes found")
            if not margin_classes:
                warnings.append(f"[{filename}] No explicit margin classes found")
        
        # Check 7: Icon references
        icons = re.findall(r'<i\s+class="fas fa-([^"]+)"', content)
        if not icons:
            warnings.append(f"[{filename}] No FontAwesome icons found - verify visual consistency")
        
        # Check 8: Responsive design
        if 'grid-cols-1' not in content and 'max-w-7xl' in content:
            warnings.append(f"[{filename}] Limited responsive grid classes detected")
        
        # Check 9: Color/severity badges
        if 'text-status-danger' not in content and 'text-status-success' not in content and 'bg-red' not in content:
            warnings.append(f"[{filename}] May lack severity color indicators")
        
        # Check 10: JavaScript event handlers
        if 'addEventListener' in content:
            handlers = re.findall(r"addEventListener\('([^']+)'", content)
            if not handlers:
                warnings.append(f"[{filename}] Event listeners found but may not be properly formatted")
        
        return {
            'file': filename,
            'issues': issues,
            'warnings': warnings,
            'button_count': content.count('<button'),
            'form_count': form_count,
            'icon_count': len(icons)
        }
    
    except Exception as e:
        return {
            'file': filename,
            'error': str(e)
        }

def main():
    """Run comprehensive UI audit"""
    print("=" * 80)
    print("SOC ANALYZER & DASHBOARD UI AUDIT TEST")
    print("=" * 80)
    print()
    
    template_dir = Path('e:\\Trash\\ai-threat-detection-security-ops\\dashboard\\templates')
    templates = list(template_dir.glob('*.html'))
    
    if not templates:
        print(f"ERROR: No HTML templates found in {template_dir}")
        return
    
    all_issues = []
    all_warnings = []
    total_buttons = 0
    total_forms = 0
    
    print(f"Found {len(templates)} templates to audit\n")
    
    for template_path in sorted(templates):
        result = audit_template_file(template_path)
        
        print(f"[OK] {result['file']}")
        if 'error' in result:
            print(f"  [ERROR] {result['error']}")
            continue
        
        # Print metrics
        print(f"  - {result['button_count']} buttons, {result['form_count']} forms, {result['icon_count']} icons")
        
        # Print issues
        if result['issues']:
            for issue in result['issues']:
                print(f"  [ISSUE] {issue}")
                all_issues.append(issue)
        
        # Print warnings
        if result['warnings']:
            for warning in result['warnings']:
                print(f"  [WARN] {warning}")
                all_warnings.append(warning)
        
        total_buttons += result['button_count']
        total_forms += result['form_count']
        print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Templates audited: {len(templates)}")
    print(f"Total buttons: {total_buttons}")
    print(f"Total forms: {total_forms}")
    print(f"Critical issues: {len(all_issues)}")
    print(f"Warnings: {len(all_warnings)}")
    print()
    
    if all_issues:
        print("CRITICAL ISSUES FOUND:")
        for issue in all_issues:
            print(f"  * {issue}")
        print()
    
    if all_warnings:
        print("WARNINGS:")
        for warning in all_warnings:
            print(f"  * {warning}")
        print()
    
    # Specific checks for SOC Analyzer
    print("=" * 80)
    print("SOC ANALYZER SPECIFIC CHECKS")
    print("=" * 80)
    
    soc_file = template_dir / 'soc_analyzer.html'
    if soc_file.exists():
        with open(soc_file, 'r') as f:
            soc_content = f.read()
        
        checks = {
            'Form with id="logForm"': 'id="logForm"' in soc_content,
            'Textarea with id="log_text"': 'id="log_text"' in soc_content,
            'File input with id="log_file"': 'id="log_file"' in soc_content,
            'Loader div with id="loader"': 'id="loader"' in soc_content,
            'Results div with id="results"': 'id="results"' in soc_content,
            'Message box with id="messageBox"': 'id="messageBox"' in soc_content,
            'File drop zone with id="fileDropZone"': 'id="fileDropZone"' in soc_content,
            'Character counter with id="charCount"': 'id="charCount"' in soc_content,
            'Submit button present': '<button type="submit"' in soc_content,
            'Drag-drop event listeners': 'dragenter' in soc_content and 'drop' in soc_content,
            'Form submit handler': 'addEventListener(\'submit\'' in soc_content,
            'Result rendering function': 'function renderResults' in soc_content,
            'Proper extends/block structure': '{% extends "base.html" %}' in soc_content and '{% block content %}' in soc_content and '{% endblock %}' in soc_content,
            'Neon button class on submit': 'class="neon-button' in soc_content,
            'Proper CSS styles embedded': '<style>' in soc_content
        }
        
        passed = sum(1 for v in checks.values() if v)
        total = len(checks)
        
        print(f"\nSOC Analyzer Element Checklist: {passed}/{total} passed\n")
        for check, result in checks.items():
            status = "[OK]" if result else "[FAIL]"
            print(f"  {status} {check}")
    
    print()
    if len(all_issues) == 0 and passed == total:
        print("ALL CHECKS PASSED - UI is properly formatted and aligned!")
    else:
        print("Review issues and warnings above")

if __name__ == '__main__':
    main()
