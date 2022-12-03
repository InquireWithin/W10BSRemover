#self-elevation sequence
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}


#GLOBAL VARIABLES
#CUSTOMIZE WHAT TO REMOVE AND WHAT TO KEEP BY EDITING THE VARIABLES HERE WITH EITHER 0 or 1. 0 indicates False/No, 1 indicates True/Yes
#Before flagging this to 1, back up your files

#do a system restore point in the current system drive for easy reversal. Will take a while.
set-variable -Name "DoSystemBackup" -Value 0

#name says it all. Hopefully this doesn't touch any of the local files. It's best to make sure you're fully synced before doing this if you are using onedrive and disabling it here.
set-variable -Name "RemoveOneDrive" -Value 1

# Leave these at 1 in nearly all cases. It's the entire premise of the script, after all.
set-variable -Name "RemoveBS" -Value 1

# Uses strings written to the hosts file to cause telemetry servers to fail to resolve. If you don't know what this is, leave it at 1.
set-variable -Name "UseHostsFile" -Value 1

#Remove all (except the pre-provisioned) apps from windows 10
set-variable -Name "RemoveDefaultWinApps" -Value 1

#keep the popular and commonly used preinstalled apps. (photos, snipping tool, camera, etc). Negated to 0 if RemoveDefaultWinApps = 1
set-variable -Name "RemoveUselessDefaultWinApps" -Value 1

#Allow Microsoft Store to be """removed""" (unusable). Why would you want to do this? It's incredibly bloated and oftentimes the OS may redirect you to it forcibly. If you've ever installed python on windows before, you know how this feels.
#Check the readme for more info on removing the ms store and its impacts.
set-variable -Name "RemoveMicrosoftStore" -Value 1

#Allow debloating actions that cannot be reversed (e.g. deleting kernel logs, etc)
set-variable -Name "AllowIrreversibleActions" -Value 1

#(Hopefully) Remove Automatic Windows Updates (or any updates that arent security related)
set-variable -Name "RemoveWindowsUpdates" -Value 1

#Remove Office. This doesn't actually delete (most) office applications but rather renders them useless. I would still recommend not running office if you plan to use this script, as office can break at the drop of a hat if certain services or servers cant be reached.
#Even if this is set to 0. If you have UseHostsFile set to 1, it's still possible that office cant be used
set-variable -Name "RemoveOffice" -Value 1

#Not always guaranteed to completely disable windows defender, especially on newer versions/isos
set-variable -Name "RemoveWinDef" -Value 1

#small tweaks to the look and flow of windows
set-variable -Name "AllowTweaks" -Value 1

#subvariables, depends on other variables triggered to 1. These will further narrow down your ideal configuration.


#prerequisite: AllowIrreversibleActions 1
#Allows for unstable debloat options, most are still in testing or known to react poorly on certain systems. Most of these effects are unknown but can usually be correlated to W10 automatically trying to course correct your actions.
#set-variable -Name "Allow-HardcoreDebloat" -Value 0 -Scope Global 
#CURRENTLY WIP

#prerequisite: UseHostsFile 1
# Uses the pihole microsoft telemetry list instead of mine. The difference being that theirs blocks servers with 0 utility to the OS and are specifically for telemetry, mine gets a lot more telemetry servers but has some adverse effects, see readme.
set-variable -Name "UseLightHostsFile" -Value 0

#creates a log file in the same directory of execution if set to 1
set-variable -Name "TraceOutput" -Value 1

#will not require the user perform a keypress for the script to close normally. Good if using this script inside another or just want it to close by itself.
set-variable -Name "AutoComplete" -Value 1




#Code starts here

#should give the directory the script runs from
$scriptdir = Split-Path $script:MyInvocation.MyCommand.Path
if ($TraceOutput -eq 1) {Start-Transcript -OutputDirectory $scriptdir} #logs output into a separate file stored in the directory this script is ran from
$fullpath = $PSScriptRoot
$sysdrive = Split-Path $fullpath -Qualifier

if ($DoSystemBackup -eq 1){
echo "Performing system backup"
Write-Host "Creating a system restore point in the current directory ($scriptdir)"
Enable-ComputerRestore -Drive "$sysdrive"
Checkpoint-Computer -Description "SystemRestorePoint" -RestorePointType "MODIFY_SETTINGS"
}

if ($RemoveBS -eq 1){
write-host "Removing bloatware, spyware, and junk..."
Import-Module AppBackgroundTask
import-module WindowsErrorReporting
Disable-AppBackgroundTaskDiagnosticLog
Disable-WindowsErrorReporting

#Scheduled task changes
write-host "Configuring scheduled tasks..."
schtasks.exe /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

#protected: TrkWks
$services = @("SgrmBroker"
"CDPUserSvc" #uses ambiguation
"EventLog"
"SysMain"
#"W32Time"
#"TimeBrokerSvc"
"DoSvc"
#"tzautoupdate"
"svsvc"
"wscsvc"
"WSearch" #does this exist anymore in newer builds?
"WMPNetworkSvc"
"DeviceAssociationService"
"RetailDemo"
"SCardSvr"
"EntAppSvc"
"Browser"
"BthAvctcpSvc"
"PerfHost"
"BcastDVRUserService" #uses ambiguation
"CaptureService" #uses ambiguation
"cbdhsvc" #uses ambiguation
"vmicheartbeat"
"FontCache"
"FontCache3.0.0.0" 
"Remoteregistry"
"DispBrokerDesktopSvc"
"DusmSvc"
"InstallService"
"LxpSvc"
"MapsBroker"
"RasMan"
"RmSvc"
"SecurityHealthService"
"SgmBroker"
#"Wcmsvc"

)

write-host "Configuring services..."
ForEach ($service in $services) {if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\$service) {
Write-Host "Changing service $service to manual"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$service" /v Start /t reg_DWORD /d 3 /f}
else {Write-Host "Service $service could not be found in the registry, skipping..."}
}

#protected: DPS, WdiSystemHost, WdiServiceHost
$removeservices = @("DiagTrack"
"TapiSrv"
"dwappushservice"
"DsSvc"
"WbioSrvc"
"diagnosticshub.standardcollector.service"
"lfsvc"
"wisvc"
"diagsvc"
"Themes"
"FDResPub"
"WdiServiceHost"
#"TokenBroker"
"edgeupdatem"
"MicrosoftEdgeElevationSvc"
"edgeupdate"

)
ForEach ($rservice in $removeservices) {if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\$rservice) {
Write-Host "Disabling service: $rservice"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$rservice" /v Start /t reg_DWORD /d 4 /f}
else {Write-Host "Service $rservice could not be found in the registry, skipping..."}
}

echo "Applying registry changes..."

echo "Turning off WinDef telemetry..."
#MS Defender-Related Telemetry
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t reg_DWORD /d 0 /f

echo "Removing clipboard telemetry..."
#Remove clipboard history
reg.exe add "HKLM\SOFTWARE\Microsoft\Clipboard" /v IsClipboardSignalProducingFeatureAvailable /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Clipboard" /v IsCloudAndHistoryFeatureAvailable /t reg_DWORD /d 0 /f

echo "Removing bloated file explorer keys..."
#Explorer keys
#protected key
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Personalization" /v AllowPersonalization /t reg_DWORD /d 0 /f
#recent doc history is inconsistent (obviously) and clutters up explorer
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsHistory /t reg_DWORD /d 1 /f
# reg key responsible for automatically running a scan on your system to upload to microsoft's remote servers
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v EnabledExecution /t reg_DWORD /d 0 /f
#edge sometimes gets used by default (even in cURL (curl) command) so I'm ensuring it doesnt send certain usage stats
reg.exe add "HKCU\SOFTWARE\Microsoft\Edge" /v UsageStatsInSample /t reg_DWORD /d 0 /f
#shouldnt make a difference anyway but if start menu returns, it'll help
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SVDEn" /v PromoteOEMTiles /t reg_DWORD /d 0 /f

echo "Negating cloudstore keys..."

#protected key
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\SystemMetaData" /v CloudStorePlatformSupported /t reg_DWORD /d 0 /f

reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\SystemMetaData" /v HasCuratedTileCollectionsInitialized /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\StoreInit" /v HasStoreCacheInitialized /t reg_DWORD /d 0 /f

#only works on x86 systems and later windows versions, havent tested this
#reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackageDetect\Microsoft-OneCore-EventLogAPI-Package~31bf3856ad364e35~amd64~~0.0.0.0" /v Microsoft-OneCore-DeviceUpdateCenter-Package~31bf3856ad364e35~amd64~en-US~10.0.19041.1202 /t reg_DWORD /d 0 /f

#risky ms edge key, protected by default
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MicrosoftEdge" /v OSIntegrationLevel /t reg_DWORD /d 0 /f

#I dont use Find My Device on windows but if you do (why), comment this next line out or delete it
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /t reg_DWORD /d 0 /f

#Remote fonts are not only bloat with a garbage premise, its also proprietary bloat just like this whole OS.
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableFontProviders /t reg_DWORD /d 0 /f

#Windows Insider preview builds are not needed. One of the script's intents is to *prevent* updating the system and *prevent* MS from forcing new features and reversions of your changes.
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v AllowBuildPreview /t reg_DWORD /d 0 /f
echo "Configuring IE..."
#They even tarnished internet explorer before tossing it by the wayside. Shame.
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" /v Enabled /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer" /v AllowServicePoweredQSA /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" /v PolicyDisableGeolocation /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v AutoSuggest /t reg_SZ /d "no" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /t reg_DWORD /d 0 /f
#do note that this line below makes your Internet Explorer possibly less secure, however if you're using IE in %CURRENT_YEAR% you arent using it for security. If you are, (why), delete the line below.
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t reg_DWORD /d 0 /f

#also big thanks to ChrisTitusTech's w10script for getting rid of a headache that comes with dual booting in one line (time inconsistency)
echo "Telling BIOS not to use UTC for time..."
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t reg_DWORD /d 0 /f

# Content Delivery is tough to remove once you've already booted the iso live and made a user account, hopefully these keys should help negate its prevalence.
# Most effective if ran before a user account is created.
echo "Removing content delievery manager..."
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t reg_DWORD /d 0 /f 
reg.exe delete HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent /f 

#remove auto update of offline maps
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v AutoDownloadAndUpdateMapData /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v AllowUntriggeredNetworkTrafficOnSettingsPage /t reg_DWORD /d 0 /f

#disable news feeds
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t reg_DWORD /d 0 /f

#Disable storage health
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageHealth" /v AllowDiskHealthModelUpdates /t reg_DWORD /d 0 /f 

#Disable Teredo
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" /v Teredo_State /t reg_SZ /d Disabled /f

#disable network status indicator (it will ping remote servers and tell the servers if you have network connection and what your active topology looks like)
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v NoActiveProbe /t reg_DWORD /d 1 /f

#turn off location storage and collection
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t reg_SZ /d "Deny" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t reg_DWORD /d 1 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessLocation /t reg_DWORD /d 0 /f

#turn off speech related functions for winapps
echo "Shutting down speech-related functions for winapps..."
reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v HasAccepted /t reg_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v AllowSpeechModelUpdate /t reg_DWORD /d 0 /f

#turn off logging of user activity (presumably non-idle uptime hours)
echo "Preventing user activity logging..."
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t reg_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t reg_DWORD /d 0 /f

#nuke Delivery Optimization (again)
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DelveryOptimization\Config" /v DODownloadMode /t reg_DWORD /d 0 /f

#nuke telemetry auto-configuring itself
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableOneSettingsDownloads /t reg_DWORD /d 1 /f

#Remove Widgets
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Widgets" /v AllowWidgets /t reg_DWORD /d 0 /f

# *** Remove Misc Telemetry & Data Collection ***
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t reg_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t reg_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t reg_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v Start /t reg_DWORD /d 0 /f

# Settings -> Privacy -> General -> Let apps use my advertising ID...
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v DisabledByGroupPolicy /t reg_DWORD /d 1 /f

# Let websites access your language settings
reg.exe add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t reg_DWORD /d 1 /f

# WiFi Sense: HotSpot Sharing: Disable
echo "Disabling hotspot-based telemetry..."
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t reg_DWORD /d 0 /f
# WiFi Sense: Shared HotSpot Auto-Connect: Disable
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t reg_DWORD /d 0 /f

# block OEM connections by the network manager
reg.exe add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t reg_DWORD /d 0 /f 

# Change Windows Updates to "Notify to schedule restart"
echo "Removing automatic restart for updates..."
reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v UxOption /t reg_DWORD /d 1 /f
# Disable P2P Update downlods outside of local network
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t reg_DWORD /d 99 /f


# *** Disable Cortana (again) ***
echo "Ensuring cortana is disabled..."
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t reg_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t reg_DWORD /d 0 /f

# *** Hide the search box from taskbar. You can still search by pressing the Win key and start typing what you're looking for ***
# 0 = hide completely, 1 = show only icon, 2 = show long search box
echo "Removing search bar from desktop..."
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t reg_DWORD /d 0 /f

# *** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
echo "Disabling Jump Lists of XAML Start Menu apps..."
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t reg_DWORD /d 0 /f

# *** Disable Suggestions in the Start Menu ***
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t reg_DWORD /d 0 /f

# shut off gamebar (fix ms-overlay issue) pt 2
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t reg_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v HistoricalCaptureEnabled /t reg_DWORD /d 0 /f

#ensure diagtrack has a much harder time if it spawns back
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t reg_DWORD /d 0 /f

echo "adding a few firewall rules..."
netsh.exe advfirewall firewall add rule name="ICP" program="C:\Windows\ImmersiveControlPanel\SystemSettings.exe" dir=out enable=yes action=block profile=any
netsh.exe advfirewall firewall add rule name="AADBroker" program="C:\Windows\SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\Microsoft.AAD.BrokerPlugin.exe" dir=out enable=yes action=block profile=any
netsh.exe advfirewall firewall add rule name="ATS" program="C:\Windows\SystemApps\Microsoft.AsyncTextService_8wekyb3d8bbwe\Microsoft.AsyncTextService.exe" dir=out enable=yes action=block profile=any
netsh.exe advfirewall firewall add rule name="BEH" program="C:\Windows\SystemApps\Microsoft.BioEnrollment_cw5n1h2txyewy\BioEnrollmentHost.exe" dir=out enable=yes action=block profile=any
netsh.exe advfirewall firewall add rule name="EC" program="C:\Windows\SystemApps\Microsoft.ECApp_8wekyb3d8bbwe\Microsoft.ECApp.exe" dir=out enable=yes action=block profile=any
netsh.exe advfirewall firewall add rule name="ASF" program="C:\Windows\SystemApps\Microsoft.Windows.AddSuggestedFoldersToLibraryDialog_cw5n1h2txyewy\AddSuggestedFoldersToLibraryDialog.exe" dir=out enable=yes action=block profile=any
netsh.exe advfirewall firewall add rule name="FE" program="C:\Windows\SystemApps\Microsoft.Windows.FileExplorer_cw5n1h2txyewy\FileExplorer.exe" dir=out enable=yes action=block profile=any
# format: netsh.exe advfirewall firewall add rule name="" program="" dir=out enable=yes action=block profile=any
#disallow any outbound connections from cortana (this shouldve already been implemented by now. But, as you should know, sometimes these changes revert, so its always good to have a second line of defense
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{0DE40C8E-C126-4A27-9371-A27DAB1039F7}" /t REG_SZ /d "v2.25|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe|Name=Block outbound Cortana|" /f

echo "Configuring scheduled tasks..."
# *** SCHEDULED TASKS tweaks ***
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

#Optional and more 'arcane' removals
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
echo "scheduled tasks configured successfully"
echo "Done."
}

if ($RemoveDefaultWinApps -eq 1) {
write-host "Removing all non-provisioned default apps..."
#I think C:\Windows\Diagtrack 's files list more in detail
Get-AppxPackage *3DBuilder* | Remove-AppxPackage
Get-AppxPackage *Cortana* | Remove-AppxPackage
Get-AppxPackage *Getstarted* | Remove-AppxPackage
Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage
Get-AppxPackage *WindowsCamera* | Remove-AppxPackage
Get-AppxPackage *bing* | Remove-AppxPackage
Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage
Get-AppxPackage *OneNote* | Remove-AppxPackage
Get-AppxPackage *photos* | Remove-AppxPackage
Get-AppxPackage *SkypeApp* | Remove-AppxPackage
Get-AppxPackage *solit* | Remove-AppxPackage
Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage
Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage
Get-AppxPackage *WindowsMaps* | Remove-AppxPackage
Get-AppxPackage *CommsPhone* | Remove-AppxPackage
Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage
Get-AppxPackage -Name *EventProvider* | Remove-AppxPackage
Get-AppxPackage -Name *Microsoft-WindowsPhone* | Remove-AppxPackage
get-appxpackage *Microsoft.XboxGamingOverlay* | remove-appxpackage
get-appxpackage *Microsoft.XboxGameOverlay* | remove-appxpackage
get-appxpackage Microsoft.MicrosoftEdge.Stable | remove-appxpackage
Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage

#remove reg.exe keys associated with them
#this part of keys came from ChrisTitusTech's w10script
echo "Removing default app reg keys..."
reg.exe delete HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent /f
#these were taken from sycnex's w10debloater
#remove background tasks
$ErrorActionPreference = 'SilentlyContinue' #avoid clogging the output w/ errors if these keys were already removed
echo "Removing default app tasks..."
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f 
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" /f 
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"/f
            
        #Windows File
reg.exe delete "HKCR\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f
            
        #registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" /f 
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f 
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" /f
            
        #Scheduled Tasks to delete
reg.exe delete "HKCR\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" /f
            
        #Windows Protocol Keys
reg.exe delete "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" /f
          
        #Windows Share Target
reg.exe delete "HKCR\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f


write-host "Done."
}

$ErrorActionPreference = 'Continue'

if ($RemoveUselessDefaultWinApps -eq 1 -and $RemoveDefaultWinApps -eq 0) {
write-host "Removing all non-provisioned useless default apps..."
#this was also taken from Sycnex's W10Debloater. I assume that a script w/ nearly 14k stars has a better idea than me of what is useful bloat. Very slightly edited.
$preinstalllist = @(

#Unnecessary Windows 10 AppX Apps
"Microsoft.BingNews"
"Microsoft.GetHelp"
"Microsoft.Getstarted"
"Microsoft.Messaging"
"Microsoft.Microsoft3DViewer"
"Microsoft.MicrosoftOfficeHub"
"Microsoft.MicrosoftSolitaireCollection"
"Microsoft.NetworkSpeedTest"
"Microsoft.News"
"Microsoft.OneConnect"
"Microsoft.People"
"Microsoft.Print3D"
"Microsoft.RemoteDesktop"
"Microsoft.SkypeApp"
"Microsoft.StorePurchaseApp"
"Microsoft.Office.Todo.List"
"Microsoft.Whiteboard"
"Microsoft.WindowsAlarms"
"microsoft.windowscommunicationsapps"
"Microsoft.WindowsFeedbackHub"
"Microsoft.WindowsMaps"
"Microsoft.WindowsSoundRecorder"
"Microsoft.Xbox.TCUI"
"Microsoft.XboxApp"
"Microsoft.XboxGameOverlay"
"Microsoft.XboxIdentityProvider"
"Microsoft.XboxSpeechToTextOverlay"
"Microsoft.ZuneMusic"
"Microsoft.ZuneVideo"

#pre-installed garbage from microsoft subsidiaries. If you need any of these applications, download the binary elsewhere. Anything built into windows is riddled w/ spyware and poor code.
"*EclipseManager*"
"*ActiproSoftwareLLC*"
"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
"*Duolingo-LearnLanguagesforFree*"
"*PandoraMediaInc*"
"*CandyCrush*"
"*BubbleWitch3Saga*"
"*Wunderlist*"
"*Flipboard*"
"*Twitter*"
"*Facebook*"
"*Spotify*"
"*Minecraft*"
"*Royal Revolt*"
"*Sway*"
"*Speed Test*"
"*Dolby*"
             
#pure bloat
"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"

#Slightly more useful but still mostly bloat
"*Microsoft.BingWeather*"
"*Microsoft.MSPaint*"
"*Microsoft.MicrosoftStickyNotes*"
#"Microsoft.WindowsCamera"
#"*Microsoft.Windows.Photos*"
#"*Microsoft.WindowsCalculator*"
#"*Microsoft.WindowsStore*"
)
    foreach ($preinstall in $preinstalllist) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        #since the addition of the nonremovable tag, this can cause errors when dealing with similar packages that are tied to the OS.
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $preinstall | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        write-host "Removing $preinstall and similar packages"
    }
    write-host "Done."
}



if ($UseHostsFile -eq 1) {
write-host "Editing hosts file..."
cp C:\Windows\System32\Drivers\etc\hosts C:\Windows\System32\Drivers\etc\hosts-BACKUP
if ($UseLightHostsFile -eq 1) {Write-Host "Using lighter variant of the hosts file..."
if (!(Test-Path $scriptdir\pihole_ms_telemetry_list.txt)) {Write-Host "Local copy of the telemetry list not found, downloading..."
curl.exe https://raw.githubusercontent.com/InquireWithin/W10BSRemover/main/pihole_ms_telemetry_list.txt > C:\Windows\System32\Drivers\etc\hosts

} else { Write-Host "Using local copy for the hosts file"
cd $scriptdir
type pihole_ms_telemetry_list.txt > C:\Windows\System32\Drivers\etc\hosts
}
}
else {
Write-Host "Using regular hosts file..."
if (!(Test-Path $scriptdir\ms_telemetry_list.txt)) {Write-Host "Local copy of the telemetry list not found, downloading..."
curl.exe https://raw.githubusercontent.com/InquireWithin/W10BSRemover/main/ms_telemetry_list.txt > C:\Windows\System32\Drivers\etc\hosts }
else {Write-Host "Using local copy for the hosts file"
cd $scriptdir
type pihole_ms_telemetry_list.txt > C:\Windows\System32\Drivers\etc\hosts}
}
write-host "Done."
}


if ($RemoveMicrosoftStore -eq 1) {
write-host "Removing MS Store..."
$services = @("APPXSVC"
"InstallService"
"Wsappx"
"PushToInstall"
)
ForEach ($service in $services) {if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\$service) {
Write-Host "Disabling MS Store service: $service"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$service" /v Start /t reg_DWORD /d 4 /f}
else {Write-Host "Service $service could not be found in the registry, skipping..."}
}
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t reg_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t reg_DWORD /d 2 /f
write-host "Done."
}



if ($RemoveOffice -eq 1) {
Write-Host "Removing office services, keys and bloat..."
$services = @("ClickToRunSvc"
"OneSyncSvc")
ForEach ($service in $services) {if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\$service) {
Write-Host "Disabling Office service: $service"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$service" /v Start /t reg_DWORD /d 4 /f}
else {Write-Host "Service $service could not be found in the registry, skipping..."}
}
$packages = @("Microsoft.Office.Lens"
"Microsoft.Office.OneNote"
"Microsoft.Office.Sway"
"Microsoft.MicrosoftOfficeHub"
)
foreach ($package in $packages) { write-host "Removing packages with names similar to $package"
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $package | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue}
write-host "Done."
}


if ($AllowIrreversibleActions -eq 1) {
Write-Host "Starting irreversibles..."
import-module DeliveryOptimization
#only deletes locally, not system wide
write-host "Cleaning local clutter..."
cmd /c "del /s /q C:\Users\%trueuser%\AppData\Local\Packages\*"
cmd /c "del /s /q C:\Users\%trueuser%\AppData\Local\Package Cache\*"
cmd /c "del /s /q C:\Users\%trueuser%\AppData\Local\GameAnalytics"

#delete live kernel log(s), freed up 1.51 GB for me
if (Test-Path "C:\Windows\LiveKernelReports\*.dmp") {
write-host "Erasing kernel log..."
cd /d C:\Windows\LiveKernelReports
del /s /q *.dmp
cd $scriptdir

write-host "Clearing the Delivery Optimization cache..."
Delete-DeliveryOptimizationCache -Force

write-host "Done."
}
}



if ($RemoveWindowsUpdates -eq 1) {
$services = @("UsoSvc"
"wuausvc"
)

ForEach ($service in $services) {if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\$service) {
Write-Host "Disabling Windows Update service: $service"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$service" /v Start /t reg_DWORD /d 4 /f}
else {Write-Host "Service $service could not be found in the registry, skipping..."}
}
echo "Applying additional registry patches..."
#nuke automatic windows update (again)
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DoNotConnectToWindowsUpdateInternetLocations /t reg_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t reg_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer /t reg_SZ /d " " /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v WUStatusServer /t reg_SZ /d " " /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v UpdateServiceUrlAlternate /t reg_SZ /d " " /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v UseWUServer /t reg_DWORD /d 1 /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t reg_DWORD /d 5 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" /v DisableRootAutoUpdate /t reg_DWORD /d 1 /f
#SmartScreen Filter: Disable
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t reg_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v ConfigureAppInstallControlEnabled /t reg_DWORD /d 1 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v ConfigureAppInstallControl /t reg_SZ /d Anywhere /f
}



if ($RemoveWinDef -eq 1) {

$services = @("WinDef"
"SecurityHealthService"
)
foreach ($service in $services) {
if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\$service) { Write-Host "Removing Windows Defender service: $service"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$service" /v Start /t reg_DWORD /d 4 /f
} else {Write-Host "Service $service could not be found in the registry, skipping..."}
}

#protected key?
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t reg_DWORD /d 1 /f
#for recent isos (I think this was patched out)
reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates\DefinitionUpdateFileSharesSources" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontReportInfectionInformation /t reg_DWORD /d 0 /f
#this is meant to be a 'service' that will show the system health of your machine, but something like this DOES NOT need to start on login, you likely didnt even know it existed.
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth" /f




}


if ($AllowTweaks -eq 1) {
# *** Show hidden files in Explorer ***
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t reg_DWORD /d 1 /f
 
# *** Show super hidden system files in Explorer ***
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t reg_DWORD /d 1 /f

# *** Show file extensions in Explorer ***
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t reg_DWORD /d 0 /f

# *** Translucent taskbar ***
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v UseOLEDTaskbarTransparency /t reg_DWORD /d 1 /f

# *** Set Windows Explorer to start on This PC instead of Quick Access ***
#1 = This PC, 2 = Quick access
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t reg_DWORD /d 1 /f
}


#this is intended to run last because the method utilized requires explorer.exe to restart
if ($RemoveOneDrive -eq 1) {
if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc) {reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v Start /t reg_DWORD /d 4 /f}
echo "Starting removal of one drive..."
cmd /c start /wait "" "C:\Windows\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
cmd /c "rd.exe C:\OneDriveTemp /Q /S >NUL 2>&1"
cmd /c "rd.exe %USERPROFILE%\OneDrive /Q /S >NUL 2>&1"
cmd /c "rd.exe %LOCALAPPDATA%\Microsoft\OneDrive /Q /S >NUL 2>&1"
cmd /c "rd.exe 'C:\ProgramData\Microsoft OneDrive' /Q /S >NUL 2>&1"
cmd /c "reg.exe add HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder /v Attributes /t reg_DWORD /d 0 /f >NUL 2>&1"
cmd /c "reg.exe add HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder /v Attributes /t reg_DWORD /d 0 /f >NUL 2>&1"
echo "OneDrive has been removed. Windows Explorer needs to be restarted."
if ($AutoComplete -eq 0) {pause}
cmd /c "start /wait TASKKILL /F /IM explorer.exe && start explorer.exe"
echo "Done."
}


