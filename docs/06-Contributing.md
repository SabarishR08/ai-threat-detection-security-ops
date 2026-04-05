# Contributing to Threat Detection Platform

Thank you for your interest in contributing to this project! This guide will help you get started.

## 📋 Table of Contents
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)

## 🚀 Getting Started

### Prerequisites
- Python 3.11 or higher
- Git
- A text editor or IDE (VS Code recommended)
- API keys for testing (optional for unit tests)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd threat-detection-platform
   ```

2. **Create virtual environment**
   ```bash
   cd backend
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   source .venv/bin/activate  # Linux/Mac
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Setup environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Run tests to verify setup**
   ```bash
   pytest backend/tests/unit/ -v
   ```

## 📁 Project Structure

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for detailed information.

Key directories:
- `backend/` - Main application code
- `backend/services/` - Business logic and integrations
- `backend/tests/` - Test suite
- `dashboard/` - Frontend templates and assets
- `docs/` - Documentation

## 💻 Coding Standards

### Python Style Guide
- Follow [PEP 8](https://pep8.org/) style guide
- Use meaningful variable and function names
- Maximum line length: 100 characters
- Use type hints where appropriate

### Code Example
```python
from typing import Dict, Optional

def check_url_safety(url: str, force_refresh: bool = False) -> Dict[str, any]:
    """
    Check if a URL is safe using multiple threat intelligence sources.
    
    Args:
        url: The URL to check
        force_refresh: Whether to bypass cache
        
    Returns:
        Dict containing safety verdict and metadata
    """
    # Implementation here
    pass
```

### Documentation
- Use docstrings for all functions, classes, and modules
- Include Args, Returns, and Raises sections
- Add inline comments for complex logic

### Import Organization
```python
# Standard library imports
import os
import sys
from typing import Dict, List

# Third-party imports
import requests
from flask import Flask

# Local imports
from backend.services import virustotal_service
from backend.models import ThreatLog
```

## 🧪 Testing

### Test Categories
1. **Unit Tests** (`tests/unit/`)
   - Test individual functions in isolation
   - Use mocks for external dependencies
   - Should be fast (< 1s per test)

2. **Integration Tests** (`tests/integration/`)
   - Test component interactions
   - Use test database
   - May mock external APIs

3. **E2E Tests** (`tests/e2e/`)
   - Full system tests
   - May require API keys
   - Longer execution time

### Writing Tests

**Unit Test Example**
```python
import pytest
from backend.services.url_intelligence import URLPreprocessor

def test_normalize_url_adds_scheme():
    """Test that URLs without scheme get https:// added."""
    processor = URLPreprocessor()
    result = processor.normalize_url("example.com")
    assert result.startswith("https://")
```

**Integration Test Example**
```python
def test_check_url_endpoint(client):
    """Test the /check-url endpoint returns valid response."""
    response = client.post('/check-url', 
                          json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert 'final_status' in data
```

### Running Tests
```bash
# Run all tests
pytest backend/tests/

# Run specific category
pytest backend/tests/unit/ -v
pytest backend/tests/integration/ -v

# Run with coverage
pytest backend/tests/ --cov=backend --cov-report=html

# Run specific test file
pytest backend/tests/unit/test_url_intelligence.py -v

# Run specific test function
pytest backend/tests/unit/test_url_intelligence.py::test_normalize_url_adds_scheme -v
```

### Test Requirements
- All new features must include tests
- Aim for >80% code coverage
- Tests must pass before PR approval
- Use descriptive test names

## 📝 Commit Guidelines

### Commit Message Format
```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples
```bash
# Good commits
feat(email-scanner): add Gmail OAuth integration
fix(api): resolve URL validation bug
docs(readme): update installation instructions
test(unit): add tests for URL preprocessing

# Bad commits
update stuff
fixed bug
changes
```

### Best Practices
- Use present tense ("add feature" not "added feature")
- First line should be ≤50 characters
- Capitalize first letter
- No period at the end
- Reference issue numbers when applicable

## 🔄 Pull Request Process

### Before Submitting

1. **Update your branch**
   ```bash
   git checkout main
   git pull origin main
   git checkout your-feature-branch
   git rebase main
   ```

2. **Run tests**
   ```bash
   pytest backend/tests/
   ```

3. **Check code style**
   ```bash
   # Install flake8 if not already installed
   pip install flake8
   flake8 backend/ --max-line-length=100
   ```

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated for changes
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Commit messages follow guidelines
- [ ] No merge conflicts
- [ ] PR description clearly explains changes

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Code follows style guide
```

### Review Process

1. Submit PR with clear description
2. Wait for automated tests to pass
3. Request review from maintainers
4. Address review comments
5. Once approved, PR will be merged

## 🐛 Bug Reports

### Before Reporting
- Check if bug already reported
- Try to reproduce on latest version
- Gather relevant information

### Bug Report Template
```markdown
**Describe the bug**
Clear description of the bug

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '...'
3. See error

**Expected behavior**
What should happen

**Screenshots**
If applicable

**Environment**
- OS: [e.g. Windows 11]
- Python version: [e.g. 3.11.0]
- Browser: [if applicable]

**Additional context**
Any other relevant information
```

## 💡 Feature Requests

### Feature Request Template
```markdown
**Is your feature request related to a problem?**
Description of the problem

**Describe the solution you'd like**
Clear description of desired feature

**Describe alternatives you've considered**
Alternative solutions considered

**Additional context**
Any other context, screenshots, etc.
```

## 🔒 Security

### Reporting Security Issues
- **DO NOT** open public issues for security vulnerabilities
- Email security concerns privately
- Include detailed description and steps to reproduce

### Security Best Practices
- Never commit API keys or credentials
- Use environment variables for secrets
- Validate all user inputs
- Keep dependencies updated
- Follow OWASP guidelines

## 📚 Additional Resources

- [Python PEP 8 Style Guide](https://pep8.org/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Pytest Documentation](https://docs.pytest.org/)
- [Git Best Practices](https://git-scm.com/book/en/v2)

## 🤝 Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the project
- Show empathy towards others

## 📞 Getting Help

- Check existing documentation
- Search closed issues
- Ask in discussions section
- Tag maintainers if urgent

## 🎓 Learning Resources

### Python & Flask
- [Real Python](https://realpython.com/)
- [Flask Mega-Tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)

### Testing
- [Pytest Tutorial](https://docs.pytest.org/en/latest/getting-started.html)
- [Testing Flask Applications](https://flask.palletsprojects.com/en/latest/testing/)

### API Integration
- [VirusTotal API Docs](https://developers.virustotal.com/reference)
- [Google Safe Browsing API](https://developers.google.com/safe-browsing)

---

Thank you for contributing! 🎉
