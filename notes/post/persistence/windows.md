# windows persistence

## scheduled tasks

schtasks /create /tn `totally_not_suspicious_task_name` /tr "`C:\totally\not\suspicious\binary.exe -e argument1 argument2`" /sc minute

- This is supposed to run every minute
- I think this works, I have been having trouble with schtasks recording arguments
