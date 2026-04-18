#!/bin/bash

# kemist Test Suite
# Comprehensive testing script for kemist vulnerability detection
# Based on sslscan's docker_test.sh approach

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Test configuration
KEMIST_PATH="../target/debug/kemist"
DOCKER_COMPOSE_FILE="docker-compose.test.yml"
TIMEOUT=10

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_test_header() {
    echo -e "\n${BOLD}=== Test $1: $2 ===${NC}"
}

print_test_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC}: $test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        if [ -n "$details" ]; then
            echo -e "  ${YELLOW}Details:${NC} $details"
        fi
    fi
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Docker is running
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    # Check if kemist binary exists
    if [ ! -f "$KEMIST_PATH" ]; then
        KEMIST_PATH="../target/release/kemist"
    fi
    
    if [ ! -f "$KEMIST_PATH" ]; then
        print_error "kemist binary not found. Please build it first with 'cargo build'"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Start test servers
start_test_servers() {
    print_status "Starting test servers..."
    
    # Stop any existing containers
    docker-compose -f "$DOCKER_COMPOSE_FILE" down > /dev/null 2>&1 || true
    
    # Build and start test servers
    docker-compose -f "$DOCKER_COMPOSE_FILE" build kemist-test-servers
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d kemist-test-servers
    
    # Wait for servers to start
    print_status "Waiting for servers to start (15 seconds)..."
    sleep 15
    
    # Check if servers are running
    if docker-compose -f "$DOCKER_COMPOSE_FILE" ps kemist-test-servers | grep -q "Up"; then
        print_success "Test servers are running"
    else
        print_error "Failed to start test servers"
        docker-compose -f "$DOCKER_COMPOSE_FILE" logs kemist-test-servers
        exit 1
    fi
}

# Run kemist and capture output
run_kemist() {
    local target="$1"
    local additional_args="$2"
    
    $KEMIST_PATH "$target" --timeout "$TIMEOUT" $additional_args 2>&1
}

# Test 1: Heartbleed vulnerability detection
test_heartbleed() {
    print_test_header "1" "Heartbleed (CVE-2014-0160) Detection"
    
    local output
    output=$(run_kemist "localhost:8443")
    
    if echo "$output" | grep -q "Heartbleed.*VULNERABLE"; then
        print_test_result "Heartbleed Detection" "PASS" "Successfully detected CVE-2014-0160"
    else
        print_test_result "Heartbleed Detection" "FAIL" "Did not detect Heartbleed vulnerability"
        echo -e "${YELLOW}Output:${NC}\n$output"
    fi
}

# Test 2: Protocol version detection
test_protocol_versions() {
    print_test_header "2" "SSL/TLS Protocol Version Detection"
    
    local output
    output=$(run_kemist "localhost:8443")
    
    local protocols_detected=0
    
    if echo "$output" | grep -q "TLSv1.2.*YES"; then
        protocols_detected=$((protocols_detected + 1))
    fi
    
    if [ $protocols_detected -gt 0 ]; then
        print_test_result "Protocol Version Detection" "PASS" "Detected $protocols_detected protocol(s)"
    else
        print_test_result "Protocol Version Detection" "FAIL" "No protocols detected"
        echo -e "${YELLOW}Output:${NC}\n$output"
    fi
}

# Test 3: Cipher suite enumeration
test_cipher_suites() {
    print_test_header "3" "Cipher Suite Enumeration"
    
    local output
    output=$(run_kemist "localhost:8443")
    
    if echo "$output" | grep -q "Supported Cipher Suites"; then
        local cipher_count
        cipher_count=$(echo "$output" | grep -c "TLS_\|SSL_\|AES\|DES" || echo "0")
        
        if [ "$cipher_count" -gt 0 ]; then
            print_test_result "Cipher Suite Enumeration" "PASS" "Found $cipher_count cipher suites"
        else
            print_test_result "Cipher Suite Enumeration" "FAIL" "No cipher suites detected"
        fi
    else
        print_test_result "Cipher Suite Enumeration" "FAIL" "Cipher suite section not found"
        echo -e "${YELLOW}Output:${NC}\n$output"
    fi
}

# Test 4: Certificate analysis
test_certificate_analysis() {
    print_test_header "4" "Certificate Analysis"
    
    local output
    output=$(run_kemist "localhost:8443")
    
    if echo "$output" | grep -q "Certificate Information"; then
        print_test_result "Certificate Analysis" "PASS" "Certificate information extracted"
    else
        print_test_result "Certificate Analysis" "FAIL" "Certificate information not found"
        echo -e "${YELLOW}Output:${NC}\n$output"
    fi
}

# Test 5: TLS renegotiation detection
test_tls_renegotiation() {
    print_test_header "5" "TLS Renegotiation Detection"
    
    local output
    output=$(run_kemist "localhost:8443")
    
    if echo "$output" | grep -q "TLS renegotiation"; then
        print_test_result "TLS Renegotiation Detection" "PASS" "Renegotiation status detected"
    else
        print_test_result "TLS Renegotiation Detection" "FAIL" "Renegotiation status not detected"
        echo -e "${YELLOW}Output:${NC}\n$output"
    fi
}

# Test 6: Fallback SCSV detection
test_fallback_scsv() {
    print_test_header "6" "Fallback SCSV Detection"
    
    local output
    output=$(run_kemist "localhost:8443")
    
    if echo "$output" | grep -q "TLS Fallback SCSV"; then
        print_test_result "Fallback SCSV Detection" "PASS" "Fallback SCSV status detected"
    else
        print_test_result "Fallback SCSV Detection" "FAIL" "Fallback SCSV status not detected"
        echo -e "${YELLOW}Output:${NC}\n$output"
    fi
}

# Test 7: Weak cipher detection (on weak cipher server)
test_weak_ciphers() {
    print_test_header "7" "Weak Cipher Detection"
    
    # Test against weak cipher server on port 8445
    local output
    output=$(run_kemist "localhost:8445")
    
    if echo "$output" | grep -q -E "(DES|RC4|NULL|weak|Weak)"; then
        print_test_result "Weak Cipher Detection" "PASS" "Weak ciphers detected"
    else
        print_test_result "Weak Cipher Detection" "FAIL" "Weak ciphers not detected"
        echo -e "${YELLOW}Output:${NC}\n$output"
    fi
}

# Test 8: Connection failure handling
test_connection_failure() {
    print_test_header "8" "Connection Failure Handling"
    
    # Test against non-existent port
    local output
    output=$(run_kemist "localhost:9999" 2>&1)
    local exit_code=$?
    
    if [ $exit_code -ne 0 ] && echo "$output" | grep -q -E "(Connection refused|timeout|failed|error)"; then
        print_test_result "Connection Failure Handling" "PASS" "Properly handled connection failure"
    else
        print_test_result "Connection Failure Handling" "FAIL" "Did not handle connection failure properly"
        echo -e "${YELLOW}Output:${NC}\n$output"
    fi
}

# Cleanup function
cleanup() {
    print_status "Cleaning up test environment..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" down > /dev/null 2>&1 || true
    print_success "Cleanup completed"
}

# Print final results
print_final_results() {
    echo -e "\n${BOLD}=== Test Results Summary ===${NC}"
    echo -e "Total tests: $TESTS_TOTAL"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}🎉 All tests passed!${NC}"
        return 0
    else
        echo -e "\n${RED}${BOLD}❌ Some tests failed${NC}"
        return 1
    fi
}

# Main execution
main() {
    echo -e "${BOLD}🔒 kemist Test Suite${NC}"
    echo -e "${BOLD}===================${NC}\n"
    
    # Set up signal handlers for cleanup
    trap cleanup EXIT
    
    check_prerequisites
    start_test_servers
    
    # Run all tests
    test_heartbleed
    test_protocol_versions
    test_cipher_suites
    test_certificate_analysis
    test_tls_renegotiation
    test_fallback_scsv
    test_weak_ciphers
    test_connection_failure
    
    print_final_results
}

# Handle command line arguments
case "${1:-}" in
    --heartbleed-only)
        print_status "Running Heartbleed-only test..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" --profile heartbleed up -d heartbleed-only
        sleep 10
        test_heartbleed
        docker-compose -f "$DOCKER_COMPOSE_FILE" --profile heartbleed down
        ;;
    --help)
        echo "Usage: $0 [OPTIONS]"
        echo "Options:"
        echo "  --heartbleed-only    Run only Heartbleed test"
        echo "  --help              Show this help message"
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac