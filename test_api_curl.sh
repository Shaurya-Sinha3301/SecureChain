#!/bin/bash

# OpenCTI API Test Script using curl
# Usage: ./test_api_curl.sh [TOKEN] [BASE_URL] [HEALTH_KEY]

BASE_URL=${2:-"http://localhost:8000"}
TOKEN=${1:-""}
HEALTH_KEY=${3:-""}

echo "🚀 OpenCTI API Testing Script (curl)"
echo "===================================="
echo "Base URL: $BASE_URL"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to test API endpoints
test_endpoint() {
    local test_name="$1"
    local url="$2"
    local method="$3"
    local headers="$4"
    local data="$5"
    
    echo -e "\n${BLUE}🔍 Testing: $test_name${NC}"
    
    if [ "$method" = "POST" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            $headers \
            -d "$data" \
            "$url" 2>/dev/null)
    else
        response=$(curl -s -w "\n%{http_code}" $headers "$url" 2>/dev/null)
    fi
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -n1)
    # Extract response body (all but last line)
    response_body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" = "200" ]; then
        echo -e "${GREEN}✅ SUCCESS: $test_name (HTTP $http_code)${NC}"
        if [ ! -z "$response_body" ] && [ "$response_body" != "null" ]; then
            echo "Response preview: $(echo "$response_body" | head -c 100)..."
        fi
    else
        echo -e "${RED}❌ FAILED: $test_name (HTTP $http_code)${NC}"
        if [ ! -z "$response_body" ]; then
            echo "Error: $response_body"
        fi
    fi
}

# Test 1: Health Check
health_url="$BASE_URL/health"
if [ ! -z "$HEALTH_KEY" ]; then
    health_url="$health_url?health_access_key=$HEALTH_KEY"
fi

test_endpoint "Health Check" "$health_url" "GET" "" ""

# Test 2: GraphQL Introspection
introspection_query='{
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } } }"
}'

headers=""
if [ ! -z "$TOKEN" ]; then
    headers="-H \"Authorization: Bearer $TOKEN\""
fi

test_endpoint "GraphQL Introspection" "$BASE_URL/graphql" "POST" "$headers" "$introspection_query"

# Test 3: Authentication Test (if token provided)
if [ ! -z "$TOKEN" ]; then
    me_query='{
        "query": "query { me { id name user_email roles { name } } }"
    }'
    
    test_endpoint "Authentication (Me Query)" "$BASE_URL/graphql" "POST" "$headers" "$me_query"
    
    # Test 4: Indicators Query
    indicators_query='{
        "query": "query { indicators(first: 5) { edges { node { id pattern indicator_types created } } } }"
    }'
    
    test_endpoint "Indicators Query" "$BASE_URL/graphql" "POST" "$headers" "$indicators_query"
    
    # Test 5: Malware Query
    malware_query='{
        "query": "query { malwares(first: 5) { edges { node { id name malware_types created } } } }"
    }'
    
    test_endpoint "Malware Query" "$BASE_URL/graphql" "POST" "$headers" "$malware_query"
else
    echo -e "\n${YELLOW}⚠️  Skipping authenticated tests - no token provided${NC}"
    echo -e "   Usage: $0 YOUR_TOKEN [BASE_URL] [HEALTH_KEY]"
fi

echo -e "\n===================================="
echo -e "${BLUE}📊 Test Summary Complete${NC}"
echo -e "\n${YELLOW}To run with authentication:${NC}"
echo -e "${NC}$0 'your_opencti_token_here'${NC}"