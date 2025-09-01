# Bosta API Security Testing Framework

A simple security testing framework for automating penetration testing of Bosta APIs.

## Project Structure

```
Automation-Security-APIs/
├── core/                   # Core framework components
│   ├── api_client.py      # HTTP client with security features
│   ├── auth.py            # Authentication & JWT testing
│   └── utils.py           # Security payload generators
├── tests/                 # Security test suites
│   ├── test_pickup.py     # Pickup API security tests
│   ├── test_bank_info.py  # Bank Info API security tests
│   └── test_forget_password.py # Password API security tests
├── configs/               # Configuration files
│   └── config.yaml        # API endpoints and settings
├── data/                  # Test data
│   └── test_data.json     # API payloads and tokens
├── requirements.txt       # Python dependencies
├── Makefile              # Quick commands
└── pytest.ini           # Test configuration
```

## What This Project Covers

### APIs Tested
- **Create Pickup API** (`POST /api/v2/pickups`)
- **Update Bank Info API** (`POST /api/v2/businesses/add-bank-info`)  
- **Forget Password API** (`POST /api/v2/users/forget-password`)


## How to Run

### 1. Setup Environment
```bash
# Clone and setup
git clone <repository>
cd Automation-Security-APIs

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Security Tests

#### Quick Commands (using Makefile)
```bash
# Run all security tests
make security-test

# Run critical tests only
make critical-test

# Run all tests
make test

# Run CI/CD tests locally
make ci-test

# Validate GitHub Actions workflows
make validate-workflows
```

#### Direct pytest Commands
```bash
# Run all security tests
python3 -m pytest tests/ -v

# Run specific test file
python3 -m pytest tests/test_bank_info.py -v

# Run tests by category
python3 -m pytest tests/ -m "critical" -v
python3 -m pytest tests/ -m "auth" -v
python3 -m pytest tests/ -m "injection" -v
```

### 3. CI/CD Automation (GitHub Actions)

The project includes automated security testing that runs:

- **On every push** to `main` or `develop` branches
- **On every pull request**
- **Daily at 2 AM UTC** (scheduled scans)
- **Manual triggers** with custom test options

#### GitHub Actions Workflows:
- **`ci-cd.yml`** - Main security testing pipeline
- **`quick-security-check.yml`** - Fast validation checks

### 4. View Results

- **Local**: Test results displayed directly in the terminal
- **CI/CD**: Check the Actions tab in your GitHub repository

## Configuration

Edit `configs/config.yaml` to change:
- API base URL
- Rate limiting settings  
- Test data parameters

Edit `data/test_data.json` to update:
- API tokens
- Test payloads
- Valid test data

## Requirements

- Python 3.9+
- Internet connection (to reach Bosta APIs)
- Valid API tokens (see `data/test_data.json`)

## Test Categories

**Total Tests**: 43 comprehensive security tests across all APIs


## Example Output

```bash
$ make security-test
Running security tests...
tests/test_bank_info.py::test_bank_info_authentication_bypass PASSED
tests/test_bank_info.py::test_bank_info_jwt_manipulation FAILED
tests/test_pickup.py::test_pickup_rate_limiting FAILED
...
```