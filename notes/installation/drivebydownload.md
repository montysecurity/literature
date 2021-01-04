# drive by downloads
This outlines how to identify and perform clickjacking vulnerabilities and exploit them as drive by downloads.

## identification
I personally use OWASP ZAP, technically, it is labeled as a "Clickjacking" flaw and is considered a "Medium" alert

## exploitation
As the name implies, clickjacking is intended to hijack a mouse click, however, if you provide a filetype that cannot be previewed in a browser, it automaticaly downloads the file.

You either have to be able to edit the sorce HTML on the website or in transit to the target.

Using a Ghidra ZIP file as an example, since ZIP files cannot be previewed, the target will automatically download the file. Put the following in the HTML.

\<iframe src="https://ghidra-sre.org/ghidra\_9.1-BETA\_DEV\_20190923.zip">
