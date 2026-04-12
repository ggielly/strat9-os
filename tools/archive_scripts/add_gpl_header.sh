#!/bin/bash

# Add GPL header to Rust files

dry_run=false
path="."
exclude=("target" "build" ".git")
website="<WEBSITE>"
repository="<REPOSITORY>"

while [[ $# -gt 0 ]]; do
    case $1 in
        -DryRun|--dry-run)
            dry_run=true
            shift
            ;;
        -Path|--path)
            path="$2"
            shift 2
            ;;
        -Exclude|--exclude)
            IFS=',' read -ra exclude <<< "$2"
            shift 2
            ;;
        -Website|--website)
            website="$2"
            shift 2
            ;;
        -Repository|--repository)
            repository="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
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

has_header() {
    local file="$1"
    head -40 "$file" | grep -qi "This file is part of.*strat9-?os"
}

add_header() {
    local file="$1"
    if [ "$dry_run" = true ]; then
        echo "Dry-run: Would add header to $file"
        return
    fi
    local content
    content=$(cat "$file")
    echo -e "$header\n\n$content" > "$file"
    echo "Added header to $file"
}

scanned=0
added=0
already=0

while IFS= read -r -d '' file; do
    scanned=$((scanned + 1))
    if ! has_header "$file"; then
        add_header "$file"
        added=$((added + 1))
    else
        already=$((already + 1))
    fi
done < <(find "$path" -type f -name "*.rs" $(printf '! -path */%s/* ' "${exclude[@]}") -print0)

if [ "$dry_run" = true ]; then
    echo "Dry-run summary: scanned=$scanned would_add=$added already=$already"
else
    echo "Summary: scanned=$scanned added=$added already=$already"
fi