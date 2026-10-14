#!/bin/bash
# Exits printing what changed when any open radare2 PR by 0verflowme gets a comment, review or inline comment newer than the start.
cd /Users/priyanshu/code/r2sleigh
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
while true; do
  for n in $(gh pr list -R radareorg/radare2 --author 0verflowme --state open --json number --jq '.[].number' 2>/dev/null); do
    new=$( { gh pr view $n -R radareorg/radare2 --json comments,reviews --jq "[.comments[],.reviews[]|select(.author.login!=\"0verflowme\")|select(.body|contains(\"codex-pull-request-review-summary\")|not)|select((.body|length)>0)|select((.createdAt // .submittedAt) > \"$since\")|\"\(.author.login): \(.body|gsub(\"\\n\";\" \")|.[0:200])\"]|.[]" 2>/dev/null; gh api repos/radareorg/radare2/pulls/$n/comments --jq ".[]|select(.user.login!=\"0verflowme\")|select(.created_at > \"$since\")|\"\(.user.login) \(.path):\(.line): \(.body|gsub(\"\\n\";\" \")|.[0:200])\"" 2>/dev/null; } )
    state=$(gh pr view $n -R radareorg/radare2 --json state --jq .state 2>/dev/null)
    if [ -n "$new" ]; then echo "#$n NEW: $new"; exit 0; fi
    if [ "$state" = MERGED ]; then echo "#$n MERGED"; exit 0; fi
  done
  sleep 1200
done
