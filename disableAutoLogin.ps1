@'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]

"AutoAdminLogon"="1"
"DefaultUserName"="sol"
"DefaultPassword"="xxxxx"
"Shell"="%programfiles(x86)%\\testnav\\testnav.exe"
'@|out-file $env:programdata\solenable.reg -force

sp "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0"
sp "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultUserName" ""
sp "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword" ""
sp "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "Shell" "explorer.exe"