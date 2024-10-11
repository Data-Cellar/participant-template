#!/bin/bash

file_path="$1"
start_marker="#<$2>"
end_marker="#</$3>"

# Temporarily store lines that are not part of a section
temp_file=$(mktemp)
in_section=false

while IFS= read -r line; do
    
    if [[ $line == *"$start_marker"* ]]; then
        in_section=true
    elif [[ $line == *"$end_marker"* ]]; then
        in_section=false
        continue
    fi

    if [ "$in_section" = false ]; then
        echo "$line" >> "$temp_file"
    fi
done < "$file_path"

# Overwrite original file with lines that are not part of a section
mv "$temp_file" "$file_path"

echo "Sections removed from $file_path"
