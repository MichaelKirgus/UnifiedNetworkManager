#!/bin/sh
# Maps changed files (one per line on stdin) to compose service names for
# `make sync`. Shared-package changes affect every plugin -> "ALL".
while IFS= read -r f; do
  case "$f" in
    api/*) echo api ;;
    webapp/*) echo webapp ;;
    mcp/*) echo mcp ;;
    plugins/*/src/*|plugins/*/docs/*|plugins/*/Dockerfile|plugins/*/package.json)
      # plugin dir = the second path component (plugins/<name>/...)
      d=${f#plugins/}; d=${d%%/*}
      echo "${d}-plugin" ;;
    packages/plugin-sdk/*|packages/snmp-client/*|packages/lancom-shared/*)
      echo ALL ;;
  esac
done
