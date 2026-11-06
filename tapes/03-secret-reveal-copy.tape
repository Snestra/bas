Output proof/vhs/03-secret-reveal-copy.gif
Source tapes/settings.tape
Type "pbcopy < /dev/null; (for s in $(seq 0 80); do printf '%3ss %s\n' $s $(pbpaste | wc -c); sleep 1; done > proof/vhs/03-clipboard-bytes.log) &" Enter
Type "./target/release/bas tui --profile bas-tui-test" Enter
Wait+Screen@30s /All secrets/
Sleep 500ms
Down Sleep 300ms
Enter Sleep 4s
Type "/BAS_TUI_DEMO_KEY" Enter
Enter Sleep 4s
Screenshot proof/vhs/03-secret-hidden.png
Type "r" Sleep 1s
Screenshot proof/vhs/03-secret-revealed.png
Type "r" Type "c" Sleep 2s
Screenshot proof/vhs/03-secret-copied.png
Sleep 30s
Screenshot proof/vhs/03-clipboard-cleared-status.png
Sleep 5s
Ctrl+C Sleep 1s
Type "wait; uniq -f1 -c proof/vhs/03-clipboard-bytes.log" Enter
Sleep 2s
Screenshot proof/vhs/03-clipboard-timeline.png
