cup all -y --ignore-checksum
gci $env:systemdrive\users\*\desktop -inc 'audacity*','google*','*acrobat*','*search*','*vlc*' -re -fo -ea 0| foreach ($_){ri $_.fullname}