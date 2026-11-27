#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="${REPO:-wrldslatt999/lr6-tls}"
if [[ "$REPO" != */* ]]; then
  echo 'REPO must be owner/name' >&2; exit 2
fi
command -v git >/dev/null || { echo 'git missing'; exit 2; }
command -v gh >/dev/null || { echo 'GitHub CLI missing'; exit 2; }
gh auth status >/dev/null || { echo 'Run gh auth login first'; exit 2; }
if [[ ! -d .git ]]; then git init -b main; fi
if [[ -z "$(git config user.name || true)" ]]; then git config user.name "${REPO%%/*}"; fi
if [[ -z "$(git config user.email || true)" ]]; then
  GITHUB_ID="$(gh api user --jq '.id')"
  git config user.email "${GITHUB_ID}+${REPO%%/*}@users.noreply.github.com"
fi
# Explicit local-secret guard before staging.
for f in users.json certs/ca.key certs/server.key logs/server.jsonl logs/client.jsonl; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    echo "ABORT: private file already tracked: $f" >&2; exit 3
  fi
done
git add -A
if git diff --cached --name-only | grep -E '(^users\.json$|^certs/[^.].*|^logs/[^.].*|\.key$|\.pem$|(^|/)\.env$)'; then
  echo 'ABORT: secret-bearing path staged; check .gitignore' >&2; exit 3
fi
if ! git diff --cached --quiet; then
  git commit -m "Implement verified SSL TLS client server lab 6"
fi
if git remote get-url origin >/dev/null 2>&1; then
  git push -u origin main
elif gh repo view "$REPO" >/dev/null 2>&1; then
  echo "Existing remote repo: $REPO"
  git remote add origin "https://github.com/${REPO}.git"
  git push -u origin main
else
  echo "Create private repository $REPO on GitHub and push? [y/N]"
  read -r answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo 'Cancelled'; exit 0; }
  gh repo create "$REPO" --private --source . --remote origin --push
fi
printf 'Repository uploaded: https://github.com/%s\n' "$REPO"
