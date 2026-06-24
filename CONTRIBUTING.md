# Contributing to ECS/EKS Security Scanner

Thank you for your interest in contributing to the ECS/EKS Security Scanner! We welcome contributions from the community.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- AWS CLI configured with appropriate credentials
- Good understanding of AWS ECS, EKS, and container security concepts

### Development Setup

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/TocConsulting/ecs-eks-security-scanner.git
   cd ecs-eks-security-scanner
   ```

2. **Create a Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Development Dependencies**
   ```bash
   # Install all development dependencies from pyproject.toml
   pip install -e ".[dev]"

   # Or install manually if needed
   pip install pytest pytest-cov black flake8 mypy "moto[ecs,eks,iam,ec2,ecr]"
   ```

## Development Workflow

### Code Style and Standards

We maintain high code quality standards using the following tools:

#### Code Formatting
```bash
# Format code with Black
black ecs_eks_security_scanner/
```

#### Code Linting
```bash
# Check code style with flake8
flake8 ecs_eks_security_scanner/

# Type checking with mypy
mypy ecs_eks_security_scanner/
```

#### Testing
```bash
# Run tests with pytest
pytest tests/

# Run tests with coverage
pytest --cov=ecs_eks_security_scanner tests/
```

### Code Quality Requirements

- **Line Length**: Maximum 79 characters (PEP8 standard)
- **Type Hints**: Required for all public functions and methods
- **Docstrings**: Required for all modules, classes, and public functions
- **Error Handling**: Proper exception handling with logging
- **Security**: No hardcoded credentials or sensitive information

## Making Changes

### Branch Naming Convention

- `feature/description-of-feature` - New features
- `bugfix/description-of-bug` - Bug fixes
- `docs/description-of-changes` - Documentation updates
- `refactor/description-of-refactor` - Code refactoring

### Commit Message Format

```
type(scope): short description

Longer description if needed

- List any breaking changes
- Reference issues: Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Pull Request Process

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Write clean, well-documented code
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # Run all checks
   black ecs_eks_security_scanner/
   flake8 ecs_eks_security_scanner/
   pytest tests/
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat(scanner): add new check for ECS task definition X"
   ```

5. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit Pull Request**
   - Provide clear description of changes
   - Reference any related issues
   - Include test results if applicable

## Testing Guidelines

### Test Structure

```
tests/
├── __init__.py
├── test_cli.py                 # CLI option tests
├── test_compliance.py          # Compliance framework tests
├── test_scoring.py             # Scoring logic tests
├── test_ecs_cluster.py         # A.1-A.5 checks
├── test_ecs_task.py            # B.1-B.10 checks
├── test_ecs_service.py         # C.1-C.5 checks
├── test_eks_cluster.py         # D.1-D.8 checks
├── test_eks_nodegroup.py       # E.1-E.4 checks
├── test_iam_security.py        # F.1-F.5 checks
├── test_logging_monitoring.py  # G.3-G.4 checks
├── test_data_protection.py     # H.2-H.4 checks
└── test_utils.py               # Utility tests
```

### Writing Tests

- Test individual functions and methods
- Use `unittest` (Python standard library) or `pytest`
- Mock AWS services using `unittest.mock` or the `moto` library
- Aim for good test coverage

### Example Test

```python
import unittest
from unittest.mock import Mock, MagicMock
from ecs_eks_security_scanner.checks.ecs_task import (
    ECSTaskChecker,
)


class TestPrivilegedCheck(unittest.TestCase):
    def setUp(self):
        self.checker = ECSTaskChecker()

    def test_privileged_container_detected(self):
        task_def = {
            "containerDefinitions": [
                {"name": "app", "privileged": True}
            ]
        }
        result = self.checker.check_privileged(task_def)
        self.assertTrue(result["has_privileged"])
```

## Architecture Guidelines

### Project Structure

```
ecs_eks_security_scanner/
├── __init__.py         # Package initialization
├── cli.py              # Command-line interface
├── scanner.py          # Main scanning orchestrator (facade)
├── compliance.py       # Compliance framework checks
├── html_reporter.py    # HTML report generation
├── utils.py            # Utility functions
├── checks/             # Modular security checker modules
│   ├── base.py         # BaseChecker (session, error handling)
│   ├── ecs_cluster.py  # A.1-A.5
│   ├── ecs_task.py     # B.1-B.10
│   ├── ecs_service.py  # C.1-C.5
│   ├── eks_cluster.py  # D.1-D.8
│   ├── eks_nodegroup.py# E.1-E.4
│   ├── iam_security.py # F.1-F.5
│   ├── logging_monitoring.py  # G.3-G.4
│   └── data_protection.py     # H.2-H.4
└── templates/          # HTML templates
```

### Adding New Features

#### New Security Checks

1. Add the check method to the appropriate checker module under `checks/`
2. Wire the check result into `ContainerSecurityScanner.scan_ecs_cluster` or `scan_eks_cluster` in `scanner.py`
3. Add issue analysis in `_analyze_ecs_issues` or `_analyze_eks_issues`
4. Add scoring deduction in `utils.calculate_ecs_security_score` / `calculate_eks_security_score`
5. Update compliance frameworks in `compliance.py` if applicable
6. Add tests for the new functionality

#### New Compliance Frameworks

1. Add framework definition to `ComplianceChecker._define_frameworks`
2. Update HTML templates if needed
3. Add framework to CLI help text and README

#### New Report Formats

1. Create new reporter class (follow `HTMLReporter` pattern)
2. Add export method to `ContainerSecurityScanner.generate_reports`
3. Update CLI options
4. Add templates if needed

## Bug Reports

When reporting bugs, please include:

- **Environment**: OS, Python version, AWS region
- **Steps to Reproduce**: Clear steps to reproduce the issue
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Error Messages**: Full error messages and stack traces
- **Configuration**: Sanitized configuration details

## Feature Requests

When requesting features, please include:

- **Use Case**: Why this feature would be useful
- **Proposed Solution**: How you envision the feature working
- **Alternatives**: Alternative approaches you've considered
- **Compatibility**: Impact on existing functionality

## Documentation

### Documentation Types

- **Code Documentation**: Inline comments and docstrings
- **User Documentation**: README and usage guides
- **Developer Documentation**: Architecture and contribution guides
- **Reference Docs**: `security-checks.md`, `compliance.md`, `remediation-guide.md`

### Documentation Standards

- Use clear, concise language
- Include code examples where helpful
- Keep documentation up-to-date with code changes
- Use proper Markdown formatting

## Security Considerations

### Reporting Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please email security issues to: contact@tocconsulting.fr

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Guidelines

- Never commit AWS credentials or other secrets
- Use environment variables for sensitive configuration
- Follow AWS security best practices
- Validate all user inputs
- Use secure coding practices

## Getting Help

- **GitHub Discussions**: For general questions and discussions
- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Check README and inline documentation first

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Release Process

1. **Version Bumping**: Use semantic versioning (MAJOR.MINOR.PATCH)
2. **Release Notes**: Document new features and fixes in GitHub release notes
3. **Testing**: Run full test suite and manual testing
4. **Documentation**: Update documentation as needed
5. **Release**: Create GitHub release with release notes
6. **Distribution**: Publish to PyPI

Thank you for contributing to making AWS container environments more secure!
