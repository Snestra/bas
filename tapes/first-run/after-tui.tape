Output proof/vhs/first-run-after-tui.gif
Source tapes/settings.tape
Env BAS_CONFIG_DIR "/tmp/bas-vhs/after-tui/bas"
Hide
Type "export PATH=/Volumes/stdNVMe/src/bitwarden-agent-secrets/target/release:$PATH; clear" Enter
Sleep 500ms
Show
Type "bas tui" Enter
Wait+Screen@10s /Access token/
Sleep 500ms
Screenshot proof/vhs/first-run-after-tui-sign-in.png
Paste
Sleep 500ms
Screenshot proof/vhs/first-run-after-tui-masked.png
Enter
Wait+Screen@40s /[0-9]+ projects?/
Sleep 2s
Ctrl+C
Sleep 1s
Hide
Type "bas auth logout default" Enter
Sleep 2s
