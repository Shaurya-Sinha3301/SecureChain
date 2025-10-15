# Simple Neo4j initialization
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("neo4j:neo4j_password"))
$headers = @{
    "Authorization" = "Basic $auth"
    "Content-Type" = "application/json"
}

Write-Host "Initializing Neo4j constraints and indexes..." -ForegroundColor Cyan

# Create constraint
$body1 = '{"statements":[{"statement":"CREATE CONSTRAINT vulnerability_finding_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.finding_id IS UNIQUE"}]}'
try {
    Invoke-RestMethod -Uri "http://localhost:7474/db/neo4j/tx/commit" -Method Post -Headers $headers -Body $body1 | Out-Null
    Write-Host "✓ Created vulnerability constraint" -ForegroundColor Green
} catch {
    Write-Host "Warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Create index
$body2 = '{"statements":[{"statement":"CREATE INDEX vulnerability_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)"}]}'
try {
    Invoke-RestMethod -Uri "http://localhost:7474/db/neo4j/tx/commit" -Method Post -Headers $headers -Body $body2 | Out-Null
    Write-Host "✓ Created severity index" -ForegroundColor Green
} catch {
    Write-Host "Warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Create sample node
$body3 = '{"statements":[{"statement":"MERGE (v:Vulnerability {finding_id: \"sample-001\", host: \"test.local\", ip: \"192.168.1.100\", service: \"ssh\", port: 22, severity: \"High\"})"}]}'
try {
    Invoke-RestMethod -Uri "http://localhost:7474/db/neo4j/tx/commit" -Method Post -Headers $headers -Body $body3 | Out-Null
    Write-Host "✓ Created sample vulnerability node" -ForegroundColor Green
} catch {
    Write-Host "Warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Test query
$testBody = '{"statements":[{"statement":"MATCH (n) RETURN labels(n) as labels, count(n) as count"}]}'
try {
    $response = Invoke-RestMethod -Uri "http://localhost:7474/db/neo4j/tx/commit" -Method Post -Headers $headers -Body $testBody
    Write-Host "Node counts:" -ForegroundColor Cyan
    foreach ($row in $response.results[0].data) {
        $labels = $row.row[0] -join ":"
        $count = $row.row[1]
        Write-Host "  $labels`: $count" -ForegroundColor White
    }
} catch {
    Write-Host "Could not retrieve node counts" -ForegroundColor Yellow
}

Write-Host "Neo4j Browser: http://localhost:7474" -ForegroundColor Magenta
Write-Host "Login: neo4j / neo4j_password" -ForegroundColor Magenta