#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <file.md>"
  exit 1
fi

INPUT="$1"
BASENAME="${INPUT%.md}"
COPY="${BASENAME}_tmp.md"

cp "$INPUT" "$COPY"

# Extract mermaid blocks into individual .mmd files, render to SVG
COUNTER=0
IN_MERMAID=0
MMD_FILE=""
while IFS= read -r LINE; do
  if [[ "$LINE" == '```mermaid' ]]; then
    IN_MERMAID=1
    MMD_FILE="${BASENAME}_mermaid_${COUNTER}.mmd"
    > "$MMD_FILE"
    continue
  fi
  if [[ $IN_MERMAID -eq 1 ]]; then
    if [[ "$LINE" == '```' ]]; then
      IN_MERMAID=0
      mmdc -i "$MMD_FILE" -o "${BASENAME}_mermaid_${COUNTER}.png" -s 3
      rm -f "$MMD_FILE"
      COUNTER=$((COUNTER + 1))
    else
      echo "$LINE" >> "$MMD_FILE"
    fi
    continue
  fi
done < "$COPY"

TOTAL=$COUNTER

# Replace mermaid blocks with image references
COUNTER=0
TMP="${COPY}.tmp"
IN_MERMAID=0
> "$TMP"
while IFS= read -r LINE; do
  if [[ "$LINE" == '```mermaid' ]]; then
    IN_MERMAID=1
    echo "![Diagram](${BASENAME}_mermaid_${COUNTER}.png)" >> "$TMP"
    continue
  fi
  if [[ $IN_MERMAID -eq 1 ]]; then
    if [[ "$LINE" == '```' ]]; then
      IN_MERMAID=0
      COUNTER=$((COUNTER + 1))
    fi
    continue
  fi
  echo "$LINE" >> "$TMP"
done < "$COPY"
mv "$TMP" "$COPY"

# Convert to Word
pandoc "$COPY" -o "${BASENAME}.docx"

# Cleanup
rm -f "$COPY"
for (( i=0; i<TOTAL; i++ )); do
  rm -f "${BASENAME}_mermaid_${i}.png"
done

echo "Created ${BASENAME}.docx"
