# linux

## writing files
it is possible to write files using `cat` in the event that you have a limited terminal. in this example "EOF" terminates `cat`.

```
cat <<EOF>users.sh
#!/bin/bash
cat /etc/shadow | egrep -v "\*|\!"
EOF
```
