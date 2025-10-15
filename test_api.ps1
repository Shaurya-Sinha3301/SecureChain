# OpenCTI API Test Script (PowerShell)
# Usage: .\test_api.ps1 -Token "your_token_here" -BaseUrl "http://localhost:8000"

param(
    [Parameter(Mandatory=$false)]
    [string]$BaseUrl = "http://localhost:8000",
    
    [Parameter(Mandatory=$false)]
    [string]$Token = "",
    
    [Parameter(Mandatory=$false)]
    [string]$HealthKey = ""
)

Write-Host "🚀 OpenCTI API Testing Script" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Base URL: $BaseUrl" -ForegroundColor Yellow

# Function to make HTTP requests
function Invoke-APITest {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [string]$TestName
    )
    
    Write-Host "`n🔍 Testing: $TestName" -ForegroundColor Blue
    
    try {
        $params = @{
            Uri = $Url
            Method = $Method
            Headers = $Headers
            TimeoutSec = 10
        }
        
        if ($Body) {
            $params.Body = $Body
            $params.ContentType = "application/json"
        }
        
        $response = Invoke-RestMethod @params
        Write-Host "✅ SUCCESS: $TestName" -ForegroundColor Green
        return @{ Success = $true; Data = $response }
    }
    catch {
        Write-Host "❌ FAILED: $TestName - $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Test 1: Health Check
$healthUrl = "$BaseUrl/health"
if ($HealthKey) {
    $healthUrl += "?health_access_key=$HealthKey"
}

$healthResult = Invoke-APITest -Url $healthUrl -TestName "Health Check"

# Test 2: GraphQL Introspection
$headers = @{}
if ($Token) {
    $headers["Authorization"] = "Bearer $Token"
}

$introspectionQuery = @{
    query = @"
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
        }
    }
"@
} | ConvertTo-Json

$introspectionResult = Invoke-APITest -Url "$BaseUrl/graphql" -Method "POST" -Headers $headers -Body $introspectionQuery -TestName "GraphQL Introspection"

# Test 3: Authentication Test (if token provided)
if ($Token) {
    $meQuery = @{
        query = @"
        query {
            me {
                id
                name
                user_email
                roles {
                    name
                }
            }
        }
"@
    } | ConvertTo-Json
    
    $authResult = Invoke-APITest -Url "$BaseUrl/graphql" -Method "POST" -Headers $headers -Body $meQuery -TestName "Authentication (Me Query)"
    
    # Test 4: Indicators Query
    $indicatorsQuery = @{
        query = @"
        query {
            indicators(first: 5) {
                edges {
                    node {
                        id
                        pattern
                        indicator_types
                        created
                    }
                }
            }
        }
"@
    } | ConvertTo-Json
    
    $indicatorsResult = Invoke-APITest -Url "$BaseUrl/graphql" -Method "POST" -Headers $headers -Body $indicatorsQuery -TestName "Indicators Query"
    
    # Test 5: Malware Query
    $malwareQuery = @{
        query = @"
        query {
            malwares(first: 5) {
                edges {
                    node {
                        id
                        name
                        malware_types
                        created
                    }
                }
            }
        }
"@
    } | ConvertTo-Json
    
    $malwareResult = Invoke-APITest -Url "$BaseUrl/graphql" -Method "POST" -Headers $headers -Body $malwareQuery -TestName "Malware Query"
} else {
    Write-Host "`n⚠️  Skipping authenticated tests - no token provided" -ForegroundColor Yellow
    Write-Host "   Use -Token parameter for full testing" -ForegroundColor Yellow
}

Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "📊 Test Summary Complete" -ForegroundColor Cyan
Write-Host "`nTo run with authentication:" -ForegroundColor Yellow
Write-Host ".\test_api.ps1 -Token 'your_opencti_token_here'" -ForegroundColor Gray