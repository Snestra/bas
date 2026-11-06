Output proof/vhs/first-run-after-login.gif
Source tapes/settings.tape
Env BAS_CONFIG_DIR "/tmp/bas-vhs/after-login/bas"
Hide
Type "export PATH=/Volumes/stdNVMe/src/bitwarden-agent-secrets/target/release:$PATH; clear" Enter
Sleep 500ms
Show
Type "bas auth login" Enter
Wait+Screen@10s /input is hidden/
Paste
Enter
Wait+Screen@30s /authenticated profile/
Sleep 1s
Type "bas auth status default" Enter
Wait+Screen@30s /authenticated to organization/
Sleep 1s
Screenshot proof/vhs/first-run-after-login.png
Hide
Type "bas auth logout default" Enter
Sleep 2s
