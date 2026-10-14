#!/bin/bash
cd /Users/priyanshu/code/r2sleigh
args=(); refs=()
while read -r b old; do
  r=$(git ls-remote origin "refs/heads/${b}" | cut -f1)
  args+=("--force-with-lease=${b}:${r}")
  refs+=("${b}:refs/heads/${b}")
done < /private/tmp/claude-501/-Users-priyanshu-code-r2sleigh/f617cb1c-6459-42bc-b410-ade5debf9280/scratchpad/old209.txt
echo "${#refs[@]} refs"
git push --atomic origin "${args[@]}" "${refs[@]}" 2>&1 | grep -v "^remote:" | tail -30
