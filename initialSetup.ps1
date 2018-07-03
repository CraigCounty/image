# >''2>&1
#works from restart

if (!(test-path ($pro = "$env:userprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"))){ni -fo $pro}
if (test-path $env:programdata\chocolatey) {cup all >''2>&1}
else {iex(iwr -useb chocolatey.org/install.ps1) >''2>&1; choco feature enable -n=allowglobalconfirmation >''2>&1}


###############
###############
###############


#really tricky apps <#
cup sqlite >''2>&1
cup psexec >''2>&1

@'
$db = "$env:programdata\Microsoft\Windows\AppRepository\StateRepository-Machine.srd"
$sql = "UPDATE Package
Set IsInBox = REPLACE(IsInBox, '1', '0')
WHERE (PackageFullName LIKE 'Microsoft.PPIP%' OR PackageFullName LIKE 'Microsoft.MicrosoftEdge_%' OR PackageFullName LIKE 'Microsoft.Windows.Holo%' OR PackageFullName LIKE 'Microsoft.Windows.Cortana%')"
$sql | sqlite3.exe $db
'@|out-file ($x = "$env:tmp\x.ps1")

psexec -i -s -d powershell -c $x

kill -n microsofte* >''2>&1
((new-object -com shell.application).namespace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').items() | ? {$_.name -eq "microsoft edge"}).verbs() | ? {$_.name.replace('&', '') -match 'unpin from taskbar'} | % {$_.doit()} >''2>&1
ri $env:userprofile\desktop\mic*.lnk
ren (ls $env:systemroot\systemapps\microsoft.microsoftedge_*) "$env:systemroot\systemapps\microsoft.microsoftedge.old"
#>

get-appxpackage -allusers | remove-appxpackage >''2>&1
get-appxprovisionedpackage -online | remove-appxprovisionedpackage -online >''2>&1


###############
###############
###############


#remove tricky apps BREAKS SYSPREP

$Definition = @"
    using System;
    using System.Runtime.InteropServices;

    public class AdjPriv {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        public static bool EnablePrivilege(long processHandle, string privilege) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
"@
$processhandle = (get-process -id $pid).handle
$type = add-type $definition -passthru
$type[0]::enableprivilege($processhandle, "setakeownershipprivilege")

function takeown-registry($key) {
    switch ($key.split('\')[0]) {
        "hkey_classes_root" {
            $reg = [microsoft.win32.registry]::classesroot
            $key = $key.substring(18)
        }
        "hkey_current_user" {
            $reg = [microsoft.win32.registry]::currentuser
            $key = $key.substring(18)
        }
        "hkey_local_machine" {
            $reg = [microsoft.win32.registry]::localmachine
            $key = $key.substring(19)
        }
    }
    $admins = new-object system.security.principal.securityidentifier("s-1-5-32-544")
    $admins = $admins.translate([system.security.principal.ntaccount])
    $key = $reg.opensubkey($key, "readwritesubtree", "takeownership")
    $acl = $key.getaccesscontrol()
    $acl.setowner($admins)
    $key.setaccesscontrol($acl)
    $acl = $key.getaccesscontrol()
    $rule = new-object system.security.accesscontrol.registryaccessrule($admins, "fullcontrol", "allow")
    $acl.setaccessrule($rule)
    $key.setaccesscontrol($acl)
}

$needles = @(
    "anytime"
    "bioenrollment"
    "browser"
    "contactsupport"
    "cortana"
    "feedback"
    "flash"
    "gaming"
    "holo"
    "maps"
    "miracastview"
    "onedrive"
    "ppiprojection"
    "sechealthui"
    "wallet"
    "xbox"
)

foreach ($needle in $needles) {
    $pkgs = (ls "hklm:\software\microsoft\windows\currentversion\component based servicing\packages" | where name -like "*$needle*")
    foreach ($pkg in $pkgs) {
        $pkgname = $pkg.name.split('\')[-1]
        takeown-registry($pkg.name)
        takeown-registry($pkg.name + "\owners")
        sp -path ("hklm:" + $pkg.name.substring(18)) -name visibility -value 1
        new-itemproperty -path ("hklm:" + $pkg.name.substring(18)) -name defvis -propertytype dword -value 2
        ri -path ("hklm:" + $pkg.name.substring(18) + "\owners")
        dism.exe /online /remove-package /packagename:$pkgname /norestart >''2>&1
    }
}
#>

#ri -re -fo "hkcu:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount"

#unpin start tiles
<#
$key = ls "hkcu:\software\microsoft\windows\currentversion\cloudstore\store\cache\DefaultAccount" -re | where { $_ -like "*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current" }
$data = (gp $key.PSPath "Data").Data[0..25] + ([byte[]](202, 50, 0, 226, 44, 1, 1, 0, 0))
sp $key.PSPath "Data" -t binary $data
#>


###############
###############
###############


#lockscreen<#
takeown /f $env:programdata\microsoft\windows\systemdata /r /a /d y
icacls $env:programdata\microsoft\windows\systemdata /grant administrator:f /t
ri -re -fo "$env:programdata\microsoft\windows\systemdata\*\readonly\lockscreen*"
takeown /f $env:systemroot\web /r /a /d y
icacls $env:systemroot\web /grant administrators:f /t
ri -re -fo ($w = "$env:tmp\w") -ea 0
cp -re -fo $env:windir\web $w
add-type -assemblyname system.drawing
$is = ls $w -re -fo -include *png, *jpg, *bmp
foreach ($i in $is) {
    $p = new-object system.drawing.bitmap($i.fullname)
    $b = new-object drawing.solidbrush ([system.drawing.color]::fromargb(255, 50, 65, 80))
    $g = [system.drawing.graphics]::fromimage($p)
    $g.fillrectangle($b, 0, 0, $p.width, $p.height)
    $g.dispose()
    $p1 = $i.fullname.replace((gi $w).fullname, "$env:systemroot\Web")
    ri $p1
    $p.save($p1)
    $p.dispose()
}
ri -re -fo $w
#>

label $env:systemdrive "Windows"


#$(gi -fo "$env:systemdrive\programdata").attributes = 'normal'
$(gi -fo "$env:userprofile\3d objects").attributes = 'hidden'
$(gi -fo "$env:userprofile\appdata").attributes = 'normal'
$(gi -fo "$env:userprofile\contacts").attributes = 'hidden'
$(gi -fo "$env:userprofile\favorites").attributes = 'hidden'
$(gi -fo "$env:userprofile\links").attributes = 'hidden'
$(gi -fo "$env:userprofile\saved games").attributes = 'hidden'
$(gi -fo "$env:userprofile\searches").attributes = 'hidden'

#task manager details<#
$t = start -windowstyle hidden -filepath taskmgr.exe -passthru
while (!($pr)) {sleep -m 250; $pr = gp "hkcu:\software\microsoft\windows\currentversion\taskmanager" "Preferences" -ea 0}
kill $t
$pr.preferences[28] = 0
sp "hkcu:\software\microsoft\windows\currentversion\taskmanager" "Preferences" -type binary -value $pr.preferences
#>

#file sharing, firewall<#
get-netfirewallrule -displaygroup 'file and printer sharing'|set-netfirewallrule -profile 'private, domain, public' -enabled true|select name, displayname, enabled, profile
(gwmi win32_terminalservicesetting -namespace root\cimv2\terminalservices).setallowtsconnections(1, 1)
(gwmi -class "win32_tsgeneralsetting" -namespace root\cimv2\terminalservices -filter "terminalname='rdp-tcp'").setuserauthenticationrequired(0)
get-netfirewallrule -displayname "remote desktop*" | set-netfirewallrule -enabled true
#>

#disable features<#
disable-windowsoptionalfeature -online -featurename internet-explorer-optional-amd64 -norestart
disable-windowsoptionalfeature -online -featurename windowsmediaplayer -norestart
disable-windowsoptionalfeature -online -featurename workfolders-client -norestart
#disable-windowsoptionalfeature -online -featurename printing-printtopdfservices-features -norestart
#disable-windowsoptionalfeature -online -featurename printing-xpsservices-features -norestart
#remove-printer -name "fax"
#>

#dns, private network<#
$iis = (gwmi win32_networkadapter).interfaceindex
foreach ($ii in $iis) {set-dnsclientserveraddress -interfaceindex $ii -serveraddress ("1.1.1.1", "1.0.0.1")}
$ix = (get-netconnectionprofile).interfaceindex
#set-netconnectionprofile -interfaceindex $ix -networkcategory private
#set-netconnectionprofile -networkcategory private
#>

#track processes<#
secedit /export /cfg c:\secpol.cfg
(gc c:\secpol.cfg).replace("AuditProcessTracking = 0", "AuditProcessTracking = 3").replace("AuditLogonEvents = 0", "AuditLogonEvents = 3").replace("AuditAccountLogon = 0", "AuditAccountLogon = 3") | out-file c:\secpol.cfg
secedit /configure /db $env:windir\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
ri c:\secpol.cfg
#>

#reg mods<#

















#reg permission<#
#
#
#
$script:u = "administrators"
$script:rs = "fullcontrol"
$script:pf = "none"
$script:if = "containerinherit"
$script:r = "allow"
$script:d = $true
$script:pi = $true
$script:p = "registry::"

function e-p {
    param($pr)
    $de =
    @'
using System;
using System.Runtime.InteropServices;
public class AdjPriv1 {
[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);
[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
[DllImport("advapi32.dll", SetLastError = true)]
internal static extern bool LookupPrivilegeValue(string host, string name,
ref long pluid);
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct TokPriv1Luid {
public int Count;
public long Luid;
public int Attr;
}
internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
internal const int TOKEN_QUERY = 0x00000008;
internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
public static bool EnablePrivilege(long processHandle, string privilege) {
bool retVal;
TokPriv1Luid tp;
IntPtr hproc = new IntPtr(processHandle);
IntPtr htok = IntPtr.Zero;
retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
ref htok);
tp.Count = 1;
tp.Luid = 0;
tp.Attr = SE_PRIVILEGE_ENABLED;
retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero,
IntPtr.Zero);
return retVal;
}
}
'@

    $ph = (ps -id $pid).handle
    $t = add-type $de -passthru
    $t[0]::enableprivilege($ph, $pr)
}

function s-oo($kp, $o) {
    ($kh, $kp) = $kp.split('\', 2)
    do {} until (e-p setakeownershipprivilege)
    if ($kh -eq "hkey_classes_root") {$ok = [microsoft.win32.registry]::classesroot.opensubkey("$kp", 'readwritesubtree', 'takeownership')}
    elseif ($kh -eq "hkey_users") {$ok = [microsoft.win32.registry]::users.opensubkey("$kp", 'readwritesubtree', 'takeownership')}
    elseif ($kh -eq "hkey_local_machine") {$ok = [microsoft.win32.registry]::localmachine.opensubkey("$kp", 'readwritesubtree', 'takeownership')}
    elseif ($kh -eq "hkey_current_config") {$ok = [microsoft.win32.registry]::currentconfig.opensubkey("$kp", 'readwritesubtree', 'takeownership')}
    $oo = new-object system.security.principal.ntaccount("$o")
    $oa2 = $ok.getaccesscontrol()
    $oa2.setowner($oo)
    $ok.setaccesscontrol($oa2)
    $ok.close()
}

function a-r($kp, $u, $rs, $pf, $if, $r) {
    ($kh, $kp) = $kp.split('\', 2)
    do {} until (e-p setakeownershipprivilege)
    if ($kh -eq "hkey_classes_root") {$ok = [microsoft.win32.registry]::classesroot.opensubkey("$kp", 'readwritesubtree', 'changepermissions')}
    elseif ($kh -eq "hkey_users") {$ok = [microsoft.win32.registry]::users.opensubkey("$kp", 'readwritesubtree', 'changepermissions')}
    elseif ($kh -eq "hkey_local_machine") {$ok = [microsoft.win32.registry]::localmachine.opensubkey("$kp", 'readwritesubtree', 'changepermissions')}
    elseif ($kh -eq "hkey_current_config") {$ok = [microsoft.win32.registry]::currentconfig.opensubkey("$kp", 'readwritesubtree', 'changepermissions')}
    $objrule = new-object system.security.accesscontrol.registryaccessrule ($u, $rs, $if, $pf, $r)
    $oa2 = $ok.getaccesscontrol()
    $oa2.setaccessrule($objrule)
    $ok.setaccesscontrol($oa2)
    $ok.close()
}

function s-oi($kp, $d, $pi) {
    $kp = $script:p + $kp
    $oa = get-acl $kp
    $oa.setaccessruleprotection($d, $pi)
    set-acl $kp $oa
}

function s-oa($k) {
    s-oo $k $script:u
    a-r $k $script:u $script:rs $script:pf $script:if $script:r
    s-oi $k $script:d $script:pi
}

function s-oag($kp) {
    foreach ($k in $(get-childitem -path $($script:p + $kp) -recurse)) {
        s-oa $k.name $script:u
    }
    s-oa $kp $script:u
}

s-oag("hkey_classes_root\clsid\{031e4825-7b94-4dc3-b131-e946b44c8dd5}\shellfolder")
#
#
#
#>




















#registry adds<#
if (!(test-path hkcr:)) {ndr hkcr registry hkey_classes_root -s global}
if (!(test-path hku:)) {ndr hku registry hkey_users -s global}
$ps =
"hkcu:\software\classes\local settings\software\microsoft\windows\currentversion\appcontainer\storage\microsoft.microsoftedge_8wekyb3d8bbwe\microsoftedge\Addons",
"hkcu:\software\classes\local settings\software\microsoft\windows\currentversion\appcontainer\storage\microsoftedge\PhishingFilter",
"hkcu:\software\microsoft\InputPersonalization",
"hkcu:\software\microsoft\InputPersonalization\TrainedDataStore",
"hkcu:\software\microsoft\internet explorer\AutoComplete",
"hkcu:\software\microsoft\Personalization\Settings",
"hkcu:\software\microsoft\Siuf\Rules",
"hkcu:\software\microsoft\windows\currentversion\AdvertisingInfo",
"hkcu:\software\microsoft\windows\currentversion\DeliveryOptimization",
"hkcu:\software\microsoft\windows\currentversion\explorer\advanced\People",
"hkcu:\software\microsoft\windows\currentversion\explorer\AutoComplete",
"hkcu:\software\microsoft\windows\currentversion\explorer\ControlPanel",
"hkcu:\software\microsoft\windows\currentversion\explorer\hidedesktopicons\ClassicStartMenu",
"hkcu:\software\microsoft\windows\currentversion\explorer\hidedesktopicons\NewStartPanel",
"hkcu:\software\microsoft\windows\currentversion\explorer\OperationStatusManager",
"hkcu:\software\microsoft\windows\currentversion\ext\settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}",
"hkcu:\software\microsoft\windows\currentversion\Holographic",
"hkcu:\software\microsoft\windows\currentversion\storagesense\parameters\StoragePolicy",
"hkcu:\software\microsoft\windows\currentversion\TaskManager",
"hkcu:\software\policies\microsoft\windows\CloudContent",
"hkcu:\software\policies\microsoft\windows\currentversion\PushNotifications",
"hkcu:\software\policies\microsoft\windows\Explorer",
"hklm:\software\microsoft\policymanager\default\wifi\AllowWiFiHotSpotReporting",
"hklm:\software\microsoft\sqmclient\Windows",
"hklm:\software\microsoft\wcmsvc\wifinetworkmanager\config",
"hklm:\software\microsoft\windows\currentversion\capabilityaccessmanager\consentstore\location",
"hklm:\software\microsoft\windows\currentversion\deliveryoptimization\config",
"hklm:\software\microsoft\windows\currentversion\explorer\FlyoutMenuSettings",
"hklm:\software\microsoft\windows\currentversion\shell extensions\Blocked",
"hklm:\software\policies\microsoft\microsoftedge\PhishingFilter",
"hklm:\software\policies\microsoft\MRT",
"hklm:\software\policies\microsoft\sqmclient",
"hklm:\software\policies\microsoft\sqmclient\windows",
"hklm:\software\policies\microsoft\windows defender\mpengine",
"hklm:\software\policies\microsoft\windows defender\Spynet",
"hklm:\software\policies\microsoft\windows nt\currentversion\networklist\signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24",
"hklm:\software\policies\microsoft\windows\AdvertisingInfo",
"hklm:\software\policies\microsoft\windows\AppCompat",
"hklm:\software\policies\microsoft\windows\CloudContent",
"hklm:\software\policies\microsoft\windows\Explorer",
"hklm:\software\policies\microsoft\windows\GameDVR",
"hklm:\software\policies\microsoft\windows\OneDrive",
"hklm:\software\policies\microsoft\windows\personalization",
"hklm:\software\policies\microsoft\windows\PreviewBuilds",
"hklm:\software\policies\microsoft\windows\Windows Search",
"hklm:\software\policies\microsoft\windows\WindowsUpdate\AU",
"hklm:\software\policies\microsoft\WindowsInkWorkspace",
"hklm:\software\policies\microsoft\WindowsStore",
"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
"HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
foreach ($p in $ps) {if (!(test-path $p)) {ni $p -ty d -f >''}}
#>

#mods<#
if (!(test-path hkcr:)) {ndr hkcr registry hkey_classes_root -s global}
if (!(test-path hku:)) {ndr hku registry hkey_users -s global}
takeown-registry "hkey_classes_root\clsid\{031e4825-7b94-4dc3-b131-e946b44c8dd5}\shellfolder"
$ms =
("hklm:\software\microsoft\windows\currentversion\shell extensions\Blocked", "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}", ""),
("hkcr:\clsid\{031e4825-7b94-4dc3-b131-e946b44c8dd5}\shellfolder", "attributes", "2962227469"), #remove libraries
#("hkcu:\control panel\accessibility\keyboard response", "AutoRepeatDelay", "160"),
#("hkcu:\control panel\accessibility\keyboard response", "AutoRepeatRate", "40"),
#("hkcu:\control panel\accessibility\keyboard response", "BounceTime", "0"),
#("hkcu:\control panel\accessibility\keyboard response", "DelayBeforeAcceptance", "0"),
#("hkcu:\control panel\accessibility\keyboard response", "Flags", "27"),
#("hkcu:\control panel\accessibility\stickykeys", "Flags", "506"),
("hkcu:\control panel\desktop", "JPEGImportQuality", 100),
#("hkcu:\control panel\keyboard", "KeyboardDelay", 0),
("hkcu:\software\classes\local settings\software\microsoft\windows\currentversion\appcontainer\storage\microsoft.microsoftedge_8wekyb3d8bbwe\microsoftedge\addons", "FlashPlayerEnabled", 0),
("hkcu:\software\microsoft\InputPersonalization", "RestrictImplicitInkCollection", 1),
("hkcu:\software\microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1),
("hkcu:\software\microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", 0),
("hkcu:\software\microsoft\internet explorer\AutoComplete", "Append Completion", "Yes"), #autocompplete
("hkcu:\software\microsoft\internet explorer\main", "Anchor Underline", "Hover"), #hover links
("hkcu:\software\microsoft\internet explorer\main", "Use FormSuggest", "Yes"),
("hkcu:\software\microsoft\personalization\settings", "AcceptedPrivacyPolicy", 0), #disable cortana
("hkcu:\software\microsoft\siuf\rules", "NumberOfSIUFInPeriod", 0), #disable feedback
("hkcu:\software\microsoft\windows\currentversion\advertisinginfo", "Enabled", 0), #disable ad id
("hkcu:\software\microsoft\windows\currentversion\apphost", "EnableWebContentEvaluation ", 0),
("hkcu:\software\microsoft\windows\currentversion\cdp", "RomeSdkChannelUserAuthzPolicy ", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "ContentDeliveryAllowed", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "OemPreInstalledAppsEnabled", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "PreInstalledAppsEnabled", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "PreInstalledAppsEverEnabled", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "SilentInstalledAppsEnabled", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "SubscribedContent-338387Enabled", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "SubscribedContent-338388Enabled", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "SubscribedContent-338389Enabled", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "SubscribedContent-353698Enabled", 0),
("hkcu:\software\microsoft\windows\currentversion\contentdeliverymanager", "SystemPaneSuggestionsEnabled", 0),
("hkcu:\software\microsoft\windows\currentversion\deliveryoptimization", "SystemSettingsDownloadMode", 3),
("hkcu:\software\microsoft\windows\currentversion\explorer", "EnableAutoTray", 0), #hide tray icons
("hkcu:\software\microsoft\windows\currentversion\explorer", "ShowFrequent", 0),
("hkcu:\software\microsoft\windows\currentversion\explorer", "ShowRecent", 0), #hide explorer recents
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "EnableBalloonTips", 0),
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "HideFileExt", 0), #show extensions
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "LaunchTo", 1), #open to this pc
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "ListviewAlphaSelect", 0),
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "ListviewShadow", 0),
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "MMTaskbarGlomLevel", 2), #taskbar titles
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "NavPaneExpandToCurrentFolder ", 1),
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "ShowSyncProviderNotifications", 0),
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "ShowTaskViewButton", 0), #disable task button
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "Start_TrackProgs", 0),
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "TaskbarAnimations", 0),
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "TaskbarGlomLevel", 2), #taskbar titles
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced", "TaskbarSmallIcons", 1), #small taskbar icons
("hkcu:\software\microsoft\windows\currentversion\explorer\advanced\People", "PeopleBand", 0), #hide people icon
("hkcu:\software\microsoft\windows\currentversion\explorer\AutoComplete", "Append Completion", "Yes"), #autocompplete
("hkcu:\software\microsoft\windows\currentversion\explorer\AutoComplete", "AutoSuggest", "Yes"), #autocompplete
("hkcu:\software\microsoft\windows\currentversion\explorer\controlpanel", "AllItemsIconView", 1),
("hkcu:\software\microsoft\windows\currentversion\explorer\controlpanel", "StartupPage", 1),
("hkcu:\software\microsoft\windows\currentversion\explorer\hidedesktopicons\classicstartmenu", "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", 0),
("hkcu:\software\microsoft\windows\currentversion\explorer\hidedesktopicons\newstartpanel", "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", 0),
("hkcu:\software\microsoft\windows\currentversion\explorer\operationstatusmanager", "EnthusiastMode", 1), #file ops
("hkcu:\software\microsoft\windows\currentversion\ext\settings\{d27cdb6e-ae6d-11cf-96b8-444553540000}", "flags", 1),
("hkcu:\software\microsoft\windows\currentversion\holographic", "FirstRunSucceeded", 0),
("hkcu:\software\microsoft\windows\currentversion\policies\explorer", "ForceClassicControlPanel", 1),
("hkcu:\software\microsoft\windows\currentversion\privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0),
("hkcu:\software\microsoft\windows\currentversion\pushNotifications", "ToastEnabled", 0),
("hkcu:\software\microsoft\windows\currentversion\search", "BingSearchEnabled", 0), #disable start web search
("hkcu:\software\microsoft\windows\currentversion\search", "CortanaConsent", 0), #disable start web search
("hkcu:\software\microsoft\windows\currentversion\search", "SearchboxTaskbarMode", 0), #no task searchbox
("hkcu:\software\microsoft\windows\currentversion\storagesense\parameters\storagepolicy", "01", 1),
("hkcu:\software\microsoft\windows\currentversion\storagesense\parameters\storagepolicy", "04", 1),
("hkcu:\software\microsoft\windows\currentversion\storagesense\parameters\storagepolicy", "08", 1),
("hkcu:\software\microsoft\windows\currentversion\storagesense\parameters\storagepolicy", "32", 0),
("hkcu:\software\microsoft\windows\currentversion\storagesense\parameters\storagepolicy", "StoragePoliciesNotified", 1),
("hkcu:\software\microsoft\windows\currentversion\themes\personalize", "appsuselighttheme", 0),
("hkcu:\software\microsoft\windows\dwm", "enableaeropeek", 0),
("hkcu:\software\policies\microsoft\windows\cloudcontent", "DisableTailoredExperiencesWithDiagnosticData", 1),
("hkcu:\software\policies\microsoft\windows\currentversion\pushnotifications", "NoTileApplicationNotification", 1),
("hkcu:\software\policies\microsoft\windows\explorer", "DisableNotificationCenter", 1), #disable action center
("hkcu:\system\gameconfigstore", "GameDVR_Enabled", 0), #disable xbox
("hklm:\software\microsoft\.netframework\v4.0.30319", "SchUseStrongCrypto", 1),
("hklm:\software\microsoft\policymanager\default\wifi\allowautoconnecttowifisensehotspots", "Value", 0),
("hklm:\software\microsoft\policymanager\default\wifi\allowwifihotspotreporting", "Value", 0), #disable wifi sense
("hklm:\software\microsoft\sqmclient\windows", "CEIPEnabled ", 0),
("hklm:\software\microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectAllowedOEM", 0),
("hklm:\software\microsoft\WcmSvc\wifinetworkmanager\config", "WiFISenseAllowed", 0),
("hklm:\software\microsoft\windows nt\currentversion\sensor\overrides\{bfa794e4-f964-4fdb-90f6-51056bfe4b44}", "SensorPermissionState", 0),
("hklm:\software\microsoft\windows nt\currentversion\sensor\overrides\{bfa794e4-f964-4fdb-90f6-51056bfe4b44}", "SensorPermissionState", 0), #disable location tracking
("hklm:\software\microsoft\windows\currentversion\appmodelunlock", "AllowAllTrustedApps", 1),
("hklm:\software\microsoft\windows\currentversion\appmodelunlock", "AllowDevelopmentWithoutDevLicense", 1), #linux dev
("hklm:\software\microsoft\Windows\currentversion\capabilityaccessmanager\consentstore\location", "Value", "Deny"),
("hklm:\software\microsoft\windows\currentversion\deliveryoptimization\config", "DODownloadMode", 1), #wupdate local only
("hklm:\software\microsoft\windows\currentversion\driversearching", "SearchOrderConfig", 1), #drivers from wupdate
("hklm:\software\microsoft\windows\currentversion\explorer", "SmartScreenEnabled", "off"), #disable smartscreen
("hklm:\software\microsoft\windows\currentversion\explorer\FlyoutMenuSettings", "ShowHibernateOption", 0), #show hibernation
("hklm:\software\microsoft\windows\currentversion\policies\datacollection", "AllowTelemetry", 0), #disable telemetry
("hklm:\software\microsoft\windows\currentversion\policies\system", "ConsentPromptBehaviorAdmin", 0), #lower uac
("hklm:\software\microsoft\windows\currentversion\policies\system", "EnableLinkedConnections", 1),
("hklm:\software\microsoft\windows\currentversion\policies\system", "PromptOnSecureDesktop", 0),

####THIS ONE BREAKS MDT RESUME, PROBABLY SYSPREP
#("hklm:\software\microsoft\windows\currentversion\policies\system\", "FilterAdministratorToken", 1), #allow admin apps

("hklm:\software\microsoft\windows\currentversion\policies\system\uipi\", "(Default)", "1"),
("hklm:\software\microsoft\windows\windows error reporting", "Disabled", 1), #disable error reporting
("hklm:\software\policies\microsoft\microsoftedge\phishingfilter", "EnabledV9", 0),
("hklm:\software\policies\microsoft\microsoftedge\phishingfilter", "EnabledV9", 0),
("hklm:\software\policies\microsoft\mrt", "DontOfferThroughWUAU", 1),
("hklm:\software\policies\microsoft\sqmclient\windows", "CEIPEnabled", 0),
("hklm:\software\policies\microsoft\windows defender\mpengine", "MpEnablePus", 1), #defender scan malware
("hklm:\software\policies\microsoft\windows defender\spynet", "DontReportInfectionInformation", 1),
("hklm:\software\policies\microsoft\windows defender\spynet", "SpynetReporting", 0),
("hklm:\software\policies\microsoft\windows defender\spynet", "SubmitSamplesConsent", 2),
("hklm:\software\policies\microsoft\windows nt\currentversion\networklist\signatures\010103000f0000f0010000000f0000f0c967a3643c3ad745950da7859209176ef5b87c875fa20df21951640e807d7c24", "Category", 1), #set unknown network private
("hklm:\software\policies\microsoft\windows\AdvertisingInfo", "DisabledByGroupPolicy", "1"),
("hklm:\software\policies\microsoft\windows\appcompat", "AITEnable", 0),
("hklm:\software\policies\microsoft\windows\appcompat", "DisableInventory ", 1),
("hklm:\software\policies\microsoft\windows\cloudcontent", "DisableDoftLanding", 1),
("hklm:\software\policies\microsoft\windows\cloudcontent", "DisableWindowsConsumerFeatures", 1),
("hklm:\software\policies\microsoft\windows\cloudcontent", "DisableWindowsSpotlightFeatures", 1),
("hklm:\software\policies\microsoft\windows\datacollection", "AllowTelemetry", 0),
("hklm:\software\policies\microsoft\windows\datacollection", "DoNotShowFeedbackNotifications", 1),
("hklm:\software\policies\microsoft\windows\explorer", "NoNewAppAlert", 1), #don't search store
("hklm:\software\policies\microsoft\windows\explorer", "NoUseStoreOpenWith", 1), #don't search store
("hklm:\software\policies\microsoft\windows\gamedvr", "AllowGameDVR", 0),
("hklm:\software\policies\microsoft\windows\onedrive", "DisableFileSyncNGSC", 1), #disable onedrive
("hklm:\software\policies\microsoft\windows\personalization", "LockScreenImage ", "$env:systemroot\web\screen\img100.jpg"),
("hklm:\software\policies\microsoft\windows\previewbuilds", "AllowBuildPreview", 0),
("hklm:\software\policies\microsoft\windows\system", "EnableActivityFeed", 0),
("hklm:\software\policies\microsoft\windows\system", "EnableCdp", 0),
("hklm:\software\policies\microsoft\windows\system", "EnableMmx", 0),
("hklm:\software\policies\microsoft\windows\system", "EnableSmartScreen", 0),
("hklm:\software\policies\microsoft\windows\system", "PublishUserActivities", 0),
("hklm:\software\policies\microsoft\windows\system", "UploadUserActivities", 0),
("hklm:\software\policies\microsoft\windows\windows search", "AllowCortana", 0),
("hklm:\software\policies\microsoft\windows\windows search", "DisableWebSearch", 1),
("hklm:\software\policies\microsoft\windows\windowsupdate\aU", "AUOptions", 4), #update options
("hklm:\software\policies\microsoft\windows\windowsupdate\au", "AUPowerManagement", 0),
("hklm:\software\policies\microsoft\windows\windowsupdate\au", "NoAutoRebootWithLoggedOnUsers", 1),
("hklm:\software\policies\microsoft\windows\windowsupdate\au", "NoAutoUpdate", 0),
("hklm:\software\policies\microsoft\windows\windowsupdate\au", "ScheduledInstallDay ", 0),
("hklm:\software\policies\microsoft\windows\windowsupdate\au", "ScheduledInstallTime", 3),
("hklm:\software\policies\microsoft\windowsinkworkspace", "AllowSuggestedAppsInWindowsInkWorkspace", 0),
("hklm:\software\policies\microsoft\windowsstore", "DisableStoreApps", 1),
("hklm:\software\policies\microsoft\windowsstore", "RemoveWindowsStore ", 1),
("hklm:\software\wow6432node\microsoft\.netframework\v4.0.30319", "SchUseStrongCrypto", 1),
("hklm:\software\wow6432node\microsoft\windows\currentversion\policies\datacollection", "AllowTelemetry", 0),
("hklm:\software\wow6432node\policies\microsoft\windows\appcompat", "DisableInventory", 1),
("hklm:\system\currentcontrolset\control\deviceguard\scenarios\hypervisorenforcedcodeintegrity", "Enabled", 1),
("hklm:\system\currentcontrolset\control\remote assistance", "fAllowToGetHelp", 0), #disable remote assist
("hklm:\system\currentcontrolset\control\session manager\power", "HibernteEnabled", 0), #enable hibernation
("hklm:\system\currentcontrolset\control\terminal server", "fDenyTSConnections ", 0), #rdp with nla
("hklm:\system\currentcontrolset\control\terminal server\winstations\rdp-tcp", "UserAuthentication", 0),
("hklm:\system\currentcontrolset\services\lfsvc\service\configuration", "Status", 0),
("hklm:\system\maps", "AutoUpdateEnabled", 0),
("hku:\.default\control panel\keyboard", "InitialKeyboardIndicators", 2147483650)

foreach ($m in $ms) {sp -fo @m}

if (!(test-path hkcr:)) {ndr hkcr registry hkey_classes_root -s global}
foreach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
    ni $("HKCR:\$type\shell\open") -fo
    ni $("HKCR:\$type\shell\open\command")
    sp $("HKCR:\$type\shell\open") "MuiVerb" -ty expandstring "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
    sp $("HKCR:\$type\shell\open\command") "(Default)" -ty expandstring "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
}



ni "HKCR:\Applications\photoviewer.dll\shell\open\command" -fo
ni "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -fo
sp "HKCR:\Applications\photoviewer.dll\shell\open" "MuiVerb" "@photoviewer.dll,-3043"
sp "HKCR:\Applications\photoviewer.dll\shell\open\command" "(Default)" -ty expandstring "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
sp "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" "Clsid" "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"

ls "hkcu:\software\microsoft\windows\currentversion\BackgroundAccessApplications"| foreach {
    sp $_.PsPath "Disabled" 1
    sp $_.PsPath "DisabledByUser" 1
}
#>

#reg removals<#
if (!(test-path hkcr:)) {ndr hkcr registry hkey_classes_root -s global}
$rds =
"hkcu:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount",
"hkcr:\*\shellex\contextmenuhandlers\sharing",
"hkcr:\allfilesystemobjects\shellex\contextmenuhandlers\{596ab062-b4d2-4215-9f74-e9109b0a8153}", # remove restore previous versions
"hkcr:\allfilesystemobjects\shellex\contextmenuhandlers\sendto",
"hkcr:\allfilesystemobjects\shellex\propertysheethandlers\{596ab062-b4d2-4215-9f74-e9109b0a8153}", # remove restore previous versions
"hkcr:\clsid\{09a47860-11b0-4da5-afa5-26d86198a780}", #scan with defender
"hkcr:\clsid\{450d8fba-ad25-11d0-98a8-0800361b1103}\shellex\contextmenuhandlers\{596ab062-b4d2-4215-9f74-e9109b0a8153}", # remove restore previous versions
"hkcr:\clsid\{450d8fba-ad25-11d0-98a8-0800361b1103}\shellex\propertysheethandlers\{596ab062-b4d2-4215-9f74-e9109b0a8153}", # remove restore previous versions
"hkcr:\directory\background\shellex\contextmenuhandlers\sharing",
"hkcr:\directory\shellex\contextmenuhandlers\{596ab062-b4d2-4215-9f74-e9109b0a8153}", # remove restore previous versions
"hkcr:\directory\shellex\contextmenuhandlers\sharing",
"hkcr:\directory\shellex\copyhookhandlers\sharing",
"hkcr:\directory\shellex\propertysheethandlers\{596ab062-b4d2-4215-9f74-e9109b0a8153}", # remove restore previous versions
"hkcr:\directory\shellex\propertysheethandlers\sharing",
"hkcr:\drive\shellex\contextmenuhandlers\{596ab062-b4d2-4215-9f74-e9109b0a8153}", # remove restore previous versions
"hkcr:\drive\shellex\contextmenuhandlers\sharing",
"hkcr:\drive\shellex\propertysheethandlers\{596ab062-b4d2-4215-9f74-e9109b0a8153}", # remove restore previous versions
"hkcr:\drive\shellex\propertysheethandlers\sharing",
"hkcr:\exefile\shellex\contextmenuhandlers\pintostartscreen",
"hkcr:\extensions\contractid\windows.backgroundtasks\packageid\46928bounde.eclipsemanager_2.2.4.51_neutral__a5h4egax66k6y", # appx stuff
"hkcr:\extensions\contractid\windows.backgroundtasks\packageid\actiprosoftwarellc.562882feeb491_2.6.18.18_neutral__24pqs290vpjk0", # appx stuff
"hkcr:\extensions\contractid\windows.backgroundtasks\packageid\microsoft.microsoftofficehub_17.7909.7600.0_x64__8wekyb3d8bbwe", # appx stuff
"hkcr:\extensions\contractid\windows.backgroundtasks\packageid\microsoft.ppiprojection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy", # appx stuff
"hkcr:\extensions\contractid\windows.backgroundtasks\packageid\microsoft.xboxgamecallableui_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy", # appx stuff
"hkcr:\extensions\contractid\windows.backgroundtasks\packageid\microsoft.xboxgamecallableui_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy", # appx stuff
"hkcr:\extensions\contractid\windows.file\packageid\actiprosoftwarellc.562882feeb491_2.6.18.18_neutral__24pqs290vpjk0", # appx stuff
"hkcr:\extensions\contractid\windows.launch\packageid\46928bounde.eclipsemanager_2.2.4.51_neutral__a5h4egax66k6y", # appx stuff
"hkcr:\extensions\contractid\windows.launch\packageid\actiprosoftwarellc.562882feeb491_2.6.18.18_neutral__24pqs290vpjk0", # appx stuff
"hkcr:\extensions\contractid\windows.launch\packageid\microsoft.ppiprojection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy", # appx stuff
"hkcr:\extensions\contractid\windows.launch\packageid\microsoft.xboxgamecallableui_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy", # appx stuff
"hkcr:\extensions\contractid\windows.launch\packageid\microsoft.xboxgamecallableui_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy", # appx stuff
"hkcr:\extensions\contractid\windows.preinstalledconfigtask\packageid\microsoft.microsoftofficehub_17.7909.7600.0_x64__8wekyb3d8bbwe", # appx stuff
"hkcr:\extensions\contractid\windows.protocol\packageid\actiprosoftwarellc.562882feeb491_2.6.18.18_neutral__24pqs290vpjk0", # appx stuff
"hkcr:\extensions\contractid\windows.protocol\packageid\microsoft.ppiprojection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy", # appx stuff
"hkcr:\extensions\contractid\windows.protocol\packageid\microsoft.xboxgamecallableui_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy", # appx stuff
"hkcr:\extensions\contractid\windows.protocol\packageid\microsoft.xboxgamecallableui_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy", # appx stuff
"hkcr:\extensions\contractid\windows.sharetarget\packageid\actiprosoftwarellc.562882feeb491_2.6.18.18_neutral__24pqs290vpjk0", # appx stuff
"hkcr:\folder\shell\pintohome",
"hkcr:\folder\shellex\contextmenuhandlers\library location",
"hkcr:\folder\shellex\contextmenuhandlers\pintostartscreen",
"hkcr:\libraryfolder\background\shellex\contextmenuhandlers\sharing",
"hkcr:\microsoft.website\shellex\contextmenuhandlers\pintostartscreen",
"hkcr:\mscfile\shellex\contextmenuhandlers\pintostartscreen",
"hkcr:\userlibraryfolder\shellex\contextmenuhandlers\sendto",
"hkcr:\userlibraryfolder\shellex\contextmenuhandlers\sharing",
"hklm:\software\classes\*\shellex\propertysheethandlers\{9b5f5829-a529-4b12-814a-e81bcb8d93fc}", #igfx
"hklm:\software\classes\directory\background\shellex\contextmenuhandlers\igfxdtcm",
"hklm:\software\classes\folder\shell\pintohome",
"hklm:\software\classes\folder\shellex\contextmenuhandlers\library location",
"hklm:\software\microsoft\active setup\installed components\{44bba840-cc51-11cf-aafa-00aa00b6015c}",
"hklm:\software\microsoft\windows\currentversion\explorer\Desktop\NameSpace\DelegateFolders",
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{088e3905-0323-4b02-9826-5d99428e115f}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{0db7e03f-fc29-4dc6-9020-ff41b59e513a}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{1cf1260c-4dd0-4ebb-811f-33c572699fde}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{374de290-123f-4565-9164-39c4925e467b}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{3add1653-eb32-4cb0-bbd7-dfa0abb5acca}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{a0953c92-50dc-43bf-be83-3742fed03c9c}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{a8cdff1c-4878-43be-b5fd-f8091c1c60d0}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{b4bfcc3a-db2c-424c-b029-7fe99a87c641}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{d3162b92-9365-467a-956b-92703aca08af}", # remove folders from 'this pc'
"hklm:\software\microsoft\windows\currentversion\explorer\mycomputer\namespace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\active setup\installed components\{44bba840-cc51-11cf-aafa-00aa00b6015c}",
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{088e3905-0323-4b02-9826-5d99428e115f}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{0db7e03f-fc29-4dc6-9020-ff41b59e513a}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{1cf1260c-4dd0-4ebb-811f-33c572699fde}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{374de290-123f-4565-9164-39c4925e467b}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{3add1653-eb32-4cb0-bbd7-dfa0abb5acca}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{a0953c92-50dc-43bf-be83-3742fed03c9c}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{a8cdff1c-4878-43be-b5fd-f8091c1c60d0}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{b4bfcc3a-db2c-424c-b029-7fe99a87c641}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{d3162b92-9365-467a-956b-92703aca08af}", # remove folders from 'this pc'
"hklm:\software\wow6432node\microsoft\windows\currentversion\explorer\mycomputer\namespace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" # remove folders from 'this pc'
foreach ($rd in $rds) {ri -re -fo -literalpath $rd}

$rs =
@("hkcu:\software\microsoft\Siuf\Rules", "PeriodInNanoSeconds"), # disable feedback
@("hkcu:\software\microsoft\windows\currentversion\policies\explorer", "confirmfiledelete"), #no del confirm
@("hklm:\software\microsoft\windows\currentversion\explorer\startupapproved\run", "rthdvcpl"), #realtek
@("hklm:\software\microsoft\windows\currentversion\run", "logitech download assistant"), # logitech startup
@("hklm:\software\microsoft\windows\currentversion\run", "rthdvbg"), # realtek startup
@("hklm:\software\microsoft\windows\currentversion\run", "rthdvcpl"), # realtek startup
@("hklm:\software\microsoft\windows\currentversion\run", "securityhealth"), # defender icon
@("hklm:\software\microsoft\windows\currentversion\run", "tvncontrol"), # tightvnc startup
@("hklm:\software\microsoft\windows\currentversion\run", "windowsdefender"), # defender icon
@("hklm:\software\policies\microsoft\windows\windowsupdate", "excludewudriversinqualityupdate") #drivers from wupdate
foreach ($r in $rs) {&rp -fo @r}
#>

#services, tasks<#
$ss =

"wsearch",
"xblauthmanager",
"xblgamesave",
"xboxgipsvc",
"xboxnetapisvc"
foreach ($s in $ss) {spsv $s -fo; set-service $s -startuptype disabled}

$t =
"\microsoft\windows\appid\smartscreenspecific",
"\microsoft\windows\application experience\aitagent",
"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
"\microsoft\windows\application experience\startupapptask",
"\Microsoft\Windows\Autochk\Proxy",
"\microsoft\windows\cloudexperiencehost\createobjecttask",
"\microsoft\windows\customer experience improvement program",
"\microsoft\windows\diskfootprint\diagnostics",
"\microsoft\windows\filehistory\file history (maintenance mode)",
"\microsoft\windows\maintenance\winsat",
"\microsoft\windows\maintenance\winsat",
"\microsoft\windows\media center",
"\microsoft\windows\pi\sqm-tasks",
"\microsoft\windows\power efficiency diagnostics\analyzesystem",
"\microsoft\windows\shell\familysafetymonitor",
"\microsoft\windows\shell\familysafetyrefresh",
"\microsoft\windows\shell\familysafetyupload",
"Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
"Microsoft\Windows\Feedback\Siuf\DmClient",
"Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
"Microsoft\Windows\Windows Error Reporting\QueueReporting",
"microsoft\xblgamesave\xblgamesavetask",
"microsoft\xblgamesave\xblgamesavetasklogon"
foreach ($t in $ts) {
    unregister-scheduledtask $task -confirm:$false
    schtasks /delete /F /TN $task
}
#>

#uninstall onedrive<#
kill -n onedrive -fo -ea 0
sleep -s 2
$o = "$env:systemroot\syswow64\onedrivesetup.exe"
if (!(test-path $o)) {$o = "$env:systemroot\system32\onedrivesetup.exe"}
start $o "/uninstall" -nonew -wait
sleep -s 2
kill -n explorer -fo -ea 0
sleep -s 2
ri -re -fo "$env:userprofile\onedrive" -ea 0
ri -re -fo "$env:localappdata\microsoft\onedrive" -ea 0
ri -re -fo "$env:programdata\microsoft onedrive" -ea 0
ri -re -fo "$env:systemdrive\onedrivetemp" -ea 0
if (!(test-path hkcr:)) {ndr hkcr registry hkey_classes_root -s global}
ri -re -fo "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -ea 0
ri -re -fo "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -ea 0

<#
@'
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\*\shell\TakeOwnership]
@="Take Ownership"
"HasLUAShield"=""
"NoWorkingDirectory"=""
"Position"="middle"

[HKEY_CLASSES_ROOT\*\shell\TakeOwnership\command]
@="powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l & pause' -Verb runAs\""
"IsolatedCommand"= "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l & pause' -Verb runAs\""

[HKEY_CLASSES_ROOT\Directory\shell\TakeOwnership]
@="Take Ownership"
"AppliesTo"="NOT (System.ItemPathDisplay:=\"C:\\Users\" OR System.ItemPathDisplay:=\"C:\\ProgramData\" OR System.ItemPathDisplay:=\"C:\\Windows\" OR System.ItemPathDisplay:=\"C:\\Windows\\System32\" OR System.ItemPathDisplay:=\"C:\\Program Files\" OR System.ItemPathDisplay:=\"C:\\Program Files (x86)\")"
"HasLUAShield"=""
"NoWorkingDirectory"=""
"Position"="middle"

[HKEY_CLASSES_ROOT\Directory\shell\TakeOwnership\command]
@="powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" /r /d y && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l /q & pause' -Verb runAs\""
"IsolatedCommand"="powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" /r /d y && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l /q & pause' -Verb runAs\""
'@|out-file ($x = "$env:tmp\takeown.reg")
regedit /S $x
#>