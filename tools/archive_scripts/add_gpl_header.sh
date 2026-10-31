#!/usr/bin/env bash
# Add or replace GPL header in Rust files (idempotent via full-header hash)
set -euo pipefail

dry_run=false
path="."
exclude=("target" "build" ".git")
website="https://www.strat9-os.org"
repository="https://github.com/ggielly/strat9-os"

while [[ $# -gt 0 ]]; do
    case $1 in
        -DryRun|--dry-run)        dry_run=true; shift ;;
        -Path|--path)             path="$2"; shift 2 ;;
        -Exclude|--exclude)       IFS=',' read -ra exclude <<< "$2"; shift 2 ;;
        -Website|--website)       website="$2"; shift 2 ;;
        -Repository|--repository) repository="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

header="/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: $website
 * Repository: $repository
 *
 * Copyright (C) 2026 Guillaume Gielly
 */"

marker_re='this file is part of strat9-?os'   # lowercase, matched on tolower()

sha() { sha256sum | cut -d' ' -f1; }

header_lines=$(printf '%s\n' "$header" | wc -l)
header_hash=$(printf '%s\n' "$header" | sha)

# Prints the last line number of the leading block comment if it contains
# the marker; prints nothing otherwise.
old_header_end() {
    awk -v re="$marker_re" '
        !started {
            if ($0 ~ /^[[:space:]]*$/) next
            if ($0 ~ /^[[:space:]]*\/\*/) started = 1
            else exit
        }
        {
            block = block tolower($0) "\n"
            line = $0
            if (NR == 1 || started) sub(/^[[:space:]]*\/\*/, "", line)
            if (index(line, "*/") > 0) {
                if (block ~ re) print NR
                exit
            }
        }
    ' "$1"
}

is_up_to_date() {
    local h
    h=$(head -n "$header_lines" "$1" | tr -d '\r' | sha)
    [[ "$h" == "$header_hash" ]]
}

write_file() {
    local file="$1" skip_to="$2" tmp
    tmp=$(mktemp "${file}.XXXXXX")
    cp -p "$file" "$tmp"
    {
        printf '%s\n\n' "$header"
        tail -n +"$((skip_to + 1))" "$file" | sed '/./,$!d'
    } > "$tmp"
    mv "$tmp" "$file"
}

find_args=(-type f -name '*.rs')
for e in "${exclude[@]}"; do
    find_args+=(-not -path "*/$e/*")
done

scanned=0; added=0; replaced=0; already=0

while IFS= read -r -d '' file; do
    scanned=$((scanned + 1))

    if is_up_to_date "$file"; then
        already=$((already + 1))
        continue
    fi

    end=$(old_header_end "$file" || true)

    if [[ -n "$end" ]]; then
        if $dry_run; then
            echo "Dry-run: would REPLACE header in $file (old header: lines 1-$end)"
        else
            write_file "$file" "$end"
            echo "Replaced header in $file"
        fi
        replaced=$((replaced + 1))
    else
        if $dry_run; then
            echo "Dry-run: would ADD header to $file"
        else
            write_file "$file" 0
            echo "Added header to $file"
        fi
        added=$((added + 1))
    fi
done < <(find "$path" "${find_args[@]}" -print0)

label="Summary"; $dry_run && label="Dry-run summary"
echo "$label: scanned=$scanned added=$added replaced=$replaced already=$already"