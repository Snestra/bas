Output proof/vhs/05-secret-delete.gif
Source tapes/settings.tape
Type "./target/release/bas-tui --profile bas-tui-test" Enter
Wait+Screen@30s /All secrets/
Sleep 500ms
Down Sleep 300ms
Enter Sleep 4s
Type "/BAS_TUI_DEMO_KEY" Enter
Type "d" Sleep 1s
Type "BAS_TUI_DEMO" Enter Sleep 1s
Screenshot proof/vhs/05-secret-delete-refused.png
Type "_KEY" Sleep 500ms
Screenshot proof/vhs/05-secret-delete-armed.png
Enter
Sleep 6s
Screenshot proof/vhs/05-secret-delete.png
Ctrl+C Sleep 1s
