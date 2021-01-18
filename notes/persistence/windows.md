# windows persistence

## scheduled tasks

schtasks /create /tn `totally_not_suspicious_task_name` /tr "`C:\totally\not\suspicious\binary.exe`" /sc minute

- This is supposed to run every minute
- Providing arguments to the program being ran has proven difficult (w/o using the GUI), will update with more examples once I get that one figured out
