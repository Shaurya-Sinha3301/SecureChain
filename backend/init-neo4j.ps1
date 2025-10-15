# Initialize Neo4j for SecureChain
$neo4jUrl = "http://localhost:7474/db/data/transaction/commit"
$username = "neo4j"
$password = "neo4j_password"

# Create authentication header
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}"))
$headers = @{
    "Authorization" = "Basic $auth"
    "Content-Type" = "application/json"
}

Write-Host "🔗 Initializing Neo4j database..." -ForegroundColor Cyan

# Read the Cypher script
$cypherScript = Get-Content "database-setup/neo4j-init/01-create-constraints.cypher" -Raw

# Execute the entire script as one transaction
try {
    $body = @{
        "statements" = @(
            @{
                "statement" = $cypherScript
            }
        )
    } | ConvertTo-Json -Depth 3

    $response = Invoke-RestMethod -Uri $neo4jUrl -Method Post -Headers $headers -Body $body -TimeoutSec 60

    if ($response.errors -and $response.errors.Count -gt 0) {
        Write-Host "❌ Errors during initialization:" -ForegroundColor Red
        foreach ($error in $response.errors) {
            Write-Host "   $($error.message)" -ForegroundColor Red
        }
        $errorCount = $response.errors.Count
        $successCount = 0
    } else {
        Write-Host "✅ Neo4j schema created successfully!" -ForegroundColor Green
        $successCount = 1
        $errorCount = 0
    }
} catch {
    Write-Host "❌ Failed to initialize Neo4j: $($_.Exception.Message)" -ForegroundColor Red
    $errorCount = 1
    $successCount = 0
}

Write-Host "✅ Neo4j initialization complete!" -ForegroundColor Green
Write-Host "   Successful statements: $successCount" -ForegroundColor White
Write-Host "   Errors/Warnings: $errorCount" -ForegroundColor White

# Test the connection with a simple query
try {
    $testBody = @{
        "statements" = @(
            @{
                "statement" = "MATCH (n) RETURN labels(n) as labels, count(n) as count"
            }
        )
    } | ConvertTo-Json -Depth 3

    $testResponse = Invoke-RestMethod -Uri $neo4jUrl -Method Post -Headers $headers -Body $testBody -TimeoutSec 10

    if ($testResponse.results -and $testResponse.results[0].data) {
        Write-Host "📊 Node counts:" -ForegroundColor Cyan
        foreach ($row in $testResponse.results[0].data) {
            $labels = $row.row[0] -join ":"
            $count = $row.row[1]
            if ($labels) {
                Write-Host "   $labels`: $count" -ForegroundColor White
            }
        }
    }
} catch {
    Write-Host "⚠️ Could not retrieve node counts: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "🌐 Neo4j Browser: http://localhost:7474" -ForegroundColor Magenta
Write-Host "🔑 Login: neo4j / neo4j_password" -ForegroundColor Magenta