#!/usr/bin/env bash

# Ensure tracked text files end with a newline. Everything tracked is checked;
# the mime-encoding probe skips the binary assets (assets/land-mask.bin), so
# there is no extension list to keep in sync with the tree.

set -e -u -o pipefail

ret=0
while IFS= read -r -d '' f; do
    if file --mime-encoding "$f" | grep -qv binary; then
        if [ -n "$(tail -c1 < "$f")" ]; then
            echo "Error: No newline at end of file $f"
            ret=1
        fi
    fi
done < <(git ls-files -z)

exit $ret
