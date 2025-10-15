# OpenCTI API Testing Scripts

This directory contains scripts to test the OpenCTI API running on localhost:8000.

## Available Scripts

### 1. Python Script (Recommended)
**File:** `test_opencti_api.py`

**Features:**
- Comprehensive testing with detailed output
- JSON output option for automation
- Proper error handling
- Colored console output

**Usage:**
```bash
# Basic health check (no authentication)
python test_opencti_api.py

# Full testing with authentication
python test_opencti_api.py --token "YOUR_OPENCTI_TOKEN"

# Custom URL and health key
python test_opencti_api.py --url "http://localhost:8080" --token "YOUR_TOKEN" --health-key "YOUR_HEALTH_KEY"

# Save results to JSON file
python test_opencti_api.py --token "YOUR_TOKEN" --output results.json
```

### 2. PowerShell Script
**File:** `test_api.ps1`

**Usage:**
```powershell
# Basic testing
.\test_api.ps1

# With authentication
.\test_api.ps1 -Token "YOUR_OPENCTI_TOKEN"

# Custom URL
.\test_api.ps1 -BaseUrl "http://localhost:8080" -Token "YOUR_TOKEN"

# With health key
.\test_api.ps1 -Token "YOUR_TOKEN" -HealthKey "YOUR_HEALTH_KEY"
```

### 3. Bash/curl Script
**File:** `test_api_curl.sh`

**Usage:**
```bash
# Make executable first
chmod +x test_api_curl.sh

# Basic testing
./test_api_curl.sh

# With authentication
./test_api_curl.sh "YOUR_OPENCTI_TOKEN"

# Custom URL and health key
./test_api_curl.sh "YOUR_TOKEN" "http://localhost:8080" "YOUR_HEALTH_KEY"
```

## Getting Your OpenCTI Token

1. **Access OpenCTI Web Interface:**
   - Open http://localhost:8000 (or your configured URL)
   - Login with your admin credentials

2. **Generate API Token:**
   - Go to Settings → Security → API Access
   - Click "Create Token"
   - Copy the generated token

3. **Alternative - Use Admin Token:**
   - Check your docker-compose environment variables
   - Look for `OPENCTI_ADMIN_TOKEN` value

## Test Coverage

All scripts test the following endpoints:

### Basic Tests (No Authentication Required)
- ✅ **Health Check** - `/health`
- ✅ **GraphQL Introspection** - `/graphql`

### Authenticated Tests (Token Required)
- ✅ **Authentication** - User info query
- ✅ **Indicators** - List threat indicators
- ✅ **Malware** - List malware entries

## Expected Results

### Successful Output Example:
```
🚀 Starting OpenCTI API Tests
==================================================
🔍 Testing Health Check...
✅ Health check passed

🔍 Testing GraphQL Introspection...
✅ GraphQL introspection successful

🔍 Testing Authentication (me query)...
✅ Authentication successful
   User: admin (admin@opencti.io)

🔍 Testing Indicators Query...
✅ Indicators query successful - Found 15 indicators

🔍 Testing Malware Query...
✅ Malware query successful - Found 8 malware entries

==================================================
📊 Test Summary:
   Health: ✅ PASS
   Introspection: ✅ PASS
   Authentication: ✅ PASS
   Indicators: ✅ PASS
   Malware: ✅ PASS

Overall: 5/5 tests passed
```

## Troubleshooting

### Common Issues:

1. **Connection Refused**
   - Ensure OpenCTI is running: `docker-compose ps`
   - Check if port 8000 is correct (might be 8080)

2. **Authentication Failed**
   - Verify your token is correct
   - Check token hasn't expired
   - Ensure token has proper permissions

3. **Health Check Fails**
   - Try with health access key
   - Check docker-compose environment variables

4. **GraphQL Errors**
   - Verify OpenCTI is fully initialized
   - Check logs: `docker-compose logs opencti`

### Port Configuration:
If your OpenCTI is running on a different port:
- Check `docker-compose.yml` for port mappings
- Common ports: 8080 (default), 8000, 4000
- Update the `--url` parameter accordingly

## Environment Variables

You can also set these as environment variables:

```bash
export OPENCTI_URL="http://localhost:8000"
export OPENCTI_TOKEN="your_token_here"
export OPENCTI_HEALTH_KEY="your_health_key"
```

Then run scripts without parameters:
```bash
python test_opencti_api.py --url "$OPENCTI_URL" --token "$OPENCTI_TOKEN"
```