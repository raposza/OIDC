#!/usr/bin/env bash
# Copyright (c) 2026 bentzn
# SPDX-License-Identifier: Apache-2.0
# Author Claude/bentzn
#
# Starts Raposza OIDC.
#
#   ./run-oidc.sh                      start from the jar that is there
#   ./run-oidc.sh --build              rebuild first, then start
#   ./run-oidc.sh --server.port=9000   any Spring argument is passed through
#
# THE ISSUER. Left alone, the service resolves its own issuer from the
# machine's routable address. That is right for a mint on a network and wrong
# behind a proxy: RFC 8414 section 3.3 compares the issuer in the discovery
# document and the `iss` of a token LITERALLY, so a service that says
# `http://host:32002` while every consumer reached `https://id.example.com`
# has every token rejected by every validator. Pin it:
#
#   ./run-oidc.sh --raposza.jwtmint.issuer=https://id.example.com
#
# TLS IS NOT HERE. The standalone deployment terminates it at nginx or
# equivalent - the operator's decision, D-774. This process serves plain HTTP
# and holds no keystore.
#
# The jar is built once and reused, and is NOT rebuilt when sources change.
# Only its absence triggers a build by itself - the same rule as
# `raposza/run-sandbox.sh`.
set -eu
cd "$(dirname "$0")"

FLAG_BUILD=0
if [ "${1:-}" = "--build" ]; then
    FLAG_BUILD=1
    shift
fi

jar_path() {
    ls -1t oidc-server/target/raposza-oidc-server-*-app.jar 2>/dev/null | head -1
}

FILE_JAR="$(jar_path || true)"

if [ -z "$FILE_JAR" ] || [ "$FLAG_BUILD" = "1" ]; then
    echo "building..."
    mvn -B install -DskipTests
    FILE_JAR="$(jar_path || true)"
fi

if [ -z "$FILE_JAR" ]; then
    echo "no jar under oidc-server/target/ - run ./build.sh" >&2
    exit 1
fi

echo "starting Raposza OIDC from $FILE_JAR"
echo "  http://localhost:32002/ui/             the web UI"
echo "  http://localhost:32002/                what it serves"
echo "  http://localhost:32002/oauth2/jwks     point a participant here"
exec java -jar "$FILE_JAR" "$@"
