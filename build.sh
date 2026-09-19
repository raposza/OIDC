#!/usr/bin/env bash
# Copyright (c) 2026 bentzn
# SPDX-License-Identifier: Apache-2.0
# Author Claude/bentzn
#
# INSTALL, not package. `raposza-auth` in the Raposza tree resolves
# raposza-oidc-core from the local repository, so a build that stopped at
# package would leave that tree compiling against whatever was there before.
set -eu
cd "$(dirname "$0")"
mvn -B install -DskipTests
echo "build: OK"
