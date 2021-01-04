# OhSINT

## Preparation

Downloaded WindowsXP.jpg from challenge prompt.

## Recon

```
file WindowsXP.jpg 
WindowsXP.jpg: JPEG image data, baseline, precision 8, 1920x1080, components 3
```

```
binwalk WindowsXP.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
515           0x203           Copyright string: "Copyright>"
615           0x267           Copyright string: "Copyright>"
```

```
exiftool WindowsXP.jpg 
ExifTool Version Number         : 11.99
File Name                       : WindowsXP.jpg
Directory                       : .
File Size                       : 229 kB
File Modification Date/Time     : 2020:06:06 19:34:32-05:00
File Access Date/Time           : 2020:06:06 19:37:45-05:00
File Inode Change Date/Time     : 2020:06:06 19:36:05-05:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 11.27
GPS Latitude                    : 54 deg 17' 41.27" N
GPS Longitude                   : 2 deg 15' 1.33" W
Copyright                       : OWoodflint
Image Width                     : 1920
Image Height                    : 1080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1920x1080
Megapixels                      : 2.1
GPS Latitude Ref                : North
GPS Longitude Ref               : West
GPS Position                    : 54 deg 17' 41.27" N, 2 deg 15' 1.33" W
``` 

The coordinates point to the East Coast of Manchester (just used 54 degrees by 2 degrees). OWoodflint returns a Twitter account (https://twitter.com/owoodflint?lang=en). There is a SSID: B4:5D:50:AA:86:41

I used WiGLE to track it to London, the BSSID is UnileverWiFi

Found a blog (https://oliverwoodflint.wordpress.com/author/owoodflint/) and a GitHub repo (https://github.com/OWoodfl1nt/people_finder). All of the answers to the room have been found.