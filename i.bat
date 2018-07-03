net use z: \\172.16.10.5\deploymentshare
xcopy /h z:\NTUSER.DAT c:\users\administrator /Y
xcopy /h z:\NTUSER.DAT c:\users\default /Y
dism /image:c:\ /import-defaultappassociations:c:\users\public\documents\defaultassociations.xml
dism /capture-image /imagefile:"z:\capture.wim" /capturedir:c:\ /name:"win"