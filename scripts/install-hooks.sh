#!/usr/bin/env bash
# Install Osiris git hooks (secret sweep). Run once after cloning:
#   ./scripts/install-hooks.sh
set -e
cd "$(dirname "$0")/.."
chmod +x scripts/git-hooks/* 2>/dev/null || true
git config core.hooksPath scripts/git-hooks
echo "✓ git hooks installed (core.hooksPath=scripts/git-hooks)."
echo "  The pre-commit secret sweep will now run on every commit."
