#!/usr/bin/env bash
# Artifact gate: fails (exit 1) if any built zip carries a number of SKILL.md
# entries other than exactly 1. The claude.ai uploader counts SKILL.md
# RECURSIVELY and refuses a bundle with 0 or 2+, so a test fixture named
# SKILL.md silently makes the whole skill uninstallable (v1.0.0/v1.1.0 shipped
# 4 and could not be installed).
#
# ⚠️ THIS IS AN ASSERTION ABOUT PACKAGING, NOT ABOUT INSTALLATION.
# Green here proves only that the archive does not contain 2+ SKILL.md. It does
# NOT prove that claude.ai accepts the upload — that is a manual step, by the
# real user path, and nothing here substitutes for it. Validating this artifact
# through a substitute path (running selftest.py instead of uploading) is
# exactly what let the original bug ship.
#
# Runs AFTER package.sh (needs the zip to exist), unlike publish-check.sh which
# audits repository CONTENT and runs BEFORE. Fail-closed.
#
# Usage: bash scripts/zip-check.sh [dist-dir]      (default: dist)
set -uo pipefail
cd "$(dirname "$0")/.."

DIST="${1:-dist}"

if [ ! -d "$DIST" ]; then
  echo "FAIL: zip-check: directory '$DIST' does not exist — run scripts/package.sh first."
  exit 1
fi

shopt -s nullglob
zips=("$DIST"/*.zip)
shopt -u nullglob

# No artifact to check is a failure, not a pass: a silently empty dist/ would
# let a broken release through on a green gate.
if [ "${#zips[@]}" -eq 0 ]; then
  echo "FAIL: zip-check: no .zip found in '$DIST' — run scripts/package.sh first."
  exit 1
fi

fail=0
for z in "${zips[@]}"; do
  if ! entries="$(unzip -Z1 "$z" 2>/dev/null)"; then
    echo "FAIL: $z — could not read archive (corrupt or unreadable)."
    fail=1
    continue
  fi

  # Only entries whose basename is exactly SKILL.md, at any depth.
  hits="$(printf '%s\n' "$entries" | grep -E '(^|/)SKILL\.md$' || true)"
  if [ -z "$hits" ]; then
    n=0
  else
    n="$(printf '%s\n' "$hits" | wc -l | tr -d ' ')"
  fi

  if [ "$n" -ne 1 ]; then
    echo "FAIL: $z carries $n SKILL.md, expected exactly 1."
    echo "      The claude.ai uploader counts SKILL.md recursively and rejects the bundle."
    echo "      SKILL.md entries found:"
    if [ "$n" -eq 0 ]; then
      echo "        (none — the skill has no manifest at all)"
    else
      printf '        %s\n' $hits
    fi
    echo "      Fix: keep ONE real SKILL.md; rename test fixtures (e.g. FIXTURE.md)."
    fail=1
  else
    echo "PASS: $(basename "$z") has exactly 1 SKILL.md ($hits)"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "zip-check: FAIL — resolve the archives above before publishing."
  exit 1
fi
echo "PASS: zip-check found exactly 1 SKILL.md in each of ${#zips[@]} zip(s)."
