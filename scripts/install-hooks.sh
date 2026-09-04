#!/bin/sh
# Point git at the repository's hooks directory. Run once per clone.
set -eu
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath scripts/hooks
echo "Hooks installed: git will run scripts/hooks/pre-push before every push."
