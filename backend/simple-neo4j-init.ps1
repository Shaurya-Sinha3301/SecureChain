# Simple Neo4j initialization
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("neo4j:neo4j_password"))
$headers = @{
    "Authorization" = "Basic $auth"
    "Content-Type" = "application/json"
}

Write-Host "🔗 Initializing Neo4j constraints and indexes..." -ForegroundColor Cyan

# List of statements to execute
$statements = @(
    "CREATE CONSTRAINT vulnerability_finding_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.finding_id IS UNIQUE",
    "CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE",
    "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT attack_pattern_id IF NOT EXISTS FOR (a:AttackPattern) REQUIRE a.mitre_id IS UNIQUE",
    "CREATE INDEX vulnerability_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
    "CREATE INDEX vulnerability_cvss IF NOT EXISTS FOR (v:Vulnerability) ON (v.cvss)",
    "CREATE INDEX vulnerability_cve IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve)",
    "CREATE INDEX vulnerability_service IF NOT EXISTS FOR (v:Vulnerability) ON (v.service)",
    "CREATE INDEX vulnerability_port IF NOT EXISTS FOR (v:Vulnerability) ON (v.port)"
)

$successCount = 0
$errorCount = 0

foreach ($statement in $statements) {
    try {
        $body = @{
            "statements" = @(
                @{
                    "statement" = $statement
                }
            )
        } | ConvertTo-Json -Depth 3

        $response = Invoke-RestMethod -Uri "http://localhost:7474/db/neo4j/tx/commit" -Method Post -Headers $headers -Body $body -TimeoutSec 30

        if ($response.errors -and $response.errors.Count -gt 0) {
            Write-Host "⚠️ Warning: $($response.errors[0].message)" -ForegroundColor Yellow
            $errorCount++
        } else {
            $successCount++
        }
    } catch {
        Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }
}

Write-Host "✅ Neo4j initialization complete!" -ForegroundColor Green
Write-Host "   Successful: $successCount" -ForegroundColor White
Write-Host "   Errors: $errorCount" -ForegroundColor White

# Create sample data
Write-Host "📊 Creating sample data..." -ForegroundColor Cyan

$sampleStatements = @(
    "MERGE (v:Vulnerability {finding_id: 'sample-001', host: 'test.local', ip: '192.168.1.100', service: 'ssh', port: 22, severity: 'High'})",
    "MERGE (h:Host {ip: '192.168.1.100', hostname: 'test.local'})",
    "MATCH (v:Vulnerability {finding_id: 'sample-001'}), (h:Host {ip: '192.168.1.100'}) MERGE (v)-[:AFFECTS]->(h)"
)

foreach ($statement in $sampleStatements) {
    try {
        $body = @{
            "statements" = @(
                @{
                    "statement" = $statement
                }
            )
        } | ConvertTo-Json -Depth 3

        Invoke-RestMethod -Uri "http://localhost:7474/db/neo4j/tx/commit" -Method Post -Headers $headers -Body $body -TimeoutSec 30 | Out-Null
    } catch {
        Write-Host "⚠️ Sample data warning: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Test query
try {
    $testBody = @{
        "statements" = @(
            @{
                "statement" = "MATCH (n) RETURN labels(n) as labels, count(n) as count"
            }
        )
    } | ConvertTo-Json -Depth 3

    $testResponse = Invoke-RestMethod -Uri "http://localhost:7474/db/neo4j/tx/commit" -Method Post -Headers $headers -Body $testBody -TimeoutSec 10

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
    Write-Host "⚠️ Could not retrieve node counts" -ForegroundColor Yellow
}

Write-Host "🌐 Neo4j Browser: http://localhost:7474" -ForegroundColor Magenta