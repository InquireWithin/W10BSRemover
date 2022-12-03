:: 14/4/22 LB orig date of creation

:: Anything that "breaks" as a result of this script can be reversed with the following commands. Usually the former does the job.
:: sfc /scannow
:: DISM.exe /Online /Cleanup-image /Scanhealth
:: DISM.exe /Online /Cleanup-image /Restorehealth

::DO NOT USE if you MUST have Microsoft Office products on your system (can be easily substituted w/ libreoffice)
::BACKUP your OneDrive files, this script will nuke it. 

:: For more info on everything here, see the README (https://github.com/InquireWithin/W10BSRemover/blob/main/README.md)

::I HIGHLY RECOMMEND that if you run this script, you use Ethernet regularly, this minimizes variance.
::If this file was flagged a security risk, know that this is why: https://www.bleepingcomputer.com/news/microsoft/windows-10-hosts-file-blocking-telemetry-is-now-flagged-as-a-risk/

::SELF ELEVATION SEQUENCE (UAC PROMPT)
@echo off

:init
 setlocal DisableDelayedExpansion
 set cmdInvoke=1
 set winSysFolder=System32
 set "batchPath=%~dpnx0"
 rem this works also from cmd shell, other than %~0
 for %%k in (%0) do set batchName=%%~nk
 set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
 setlocal EnableDelayedExpansion


:checkPrivileges
  NET FILE 1>NUL 2>NUL
  if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
  if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
  ECHO.
  ECHO **************************************
  ECHO Invoking UAC for Privilege Escalation
  ECHO **************************************

  ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
  ECHO args = "ELEV " >> "%vbsGetPrivileges%"
  ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
  ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
  ECHO Next >> "%vbsGetPrivileges%"
  
  if '%cmdInvoke%'=='1' goto InvokeCmd 

  ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
  goto ExecElevation

:InvokeCmd
  ECHO args = "/c """ + "!batchPath!" + """ " + args >> "%vbsGetPrivileges%"
  ECHO UAC.ShellExecute "%SystemRoot%\%winSysFolder%\cmd.exe", args, "", "runas", 1 >> "%vbsGetPrivileges%"

:ExecElevation
 "%SystemRoot%\%winSysFolder%\WScript.exe" "%vbsGetPrivileges%" %*
 exit /B

:gotPrivileges
 setlocal & cd /d %~dp0
 if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

cd %~dp0
cls
ver
echo(^
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR^
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,^
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE^
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,^
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE^
 SOFTWARE.
)

@echo off
SETLOCAL ENABLEDELAYEDEXPANSION
goto one


::"main" function
:one
::for users that were using a microsoft account and switched to local later (i recommend this if you are using ms account for login) and the new username is different
::manually change this if needed or the situation above applies to you
set trueuser=%username%


echo "Trueuser: %trueuser%"
echo "Username: %username%"
echo "Running from dir: %~dp0"
echo "Script name: %~nx0"
echo "Script full path: %~0"

::Back up and flush current hosts file and start
type %SystemRoot%\System32\drivers\etc\hosts > %SystemRoot%\System32\drivers\etc\hosts-BACKUP
::back up the windows store access control lists, stored in %SystemRoot%\System32
::icacls "%ProgramFiles%\WindowsApps" /save WindowsApps.acl
:: if a serious error occurs w/ this use: icacls "%ProgramFiles%" /restore WindowsApps.acl

::Typical services I obtained from autoruns and services.msc, the more niche ones I grabbed from https://github.com/ChrisTitusTech/win10script ; WdNisSvc appears unremovable. ; sc query to check all running svcs

::removed Winmgmt from this list until properly tested
::Its likely better to add the reg keys themselves (setting Start to 4 (disabled) in the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services rather than use sc)	
::Some of these services are protected on newer builds. Can hopefully mitigate this later by using the binPath option of sc, or better yet using icacls to deny system access
::protected: Trkwks, AppXSvc?
set miscservices=APPXSVC SgrmBroker DusmSvc FontCache3.0.0.0 EventLog DoSvc FontCache InstallService Wsappx PushToInstall SysMain W32Time TimeBrokerSvc ClickToRunSvc OneSyncSvc UsoSvc tzautoupdate wscsvc svsvc wisvc WSearch wuauserv SecurityHealthService WMPNetworkSvc DeviceAssociationService RetailDemo SCardSvr EntAppSvc Browser BthAvctcpSvc edgeupdate MicrosoftEdgeElevationService edgeupdatem SEMgrSvc PerfHost BcastDVRUserService CaptureService cbdhsvc CDPUserSvc vmicheartbeat
for %%p in (%miscservices%) do ( 
sc stop %%p >NUL
::reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%%p" /v Start /t REG_DWORD /d 3 /f <- cant do w/o checking if key exists
sc config %%p start= demand 
echo "Service %%p changed to demand (manual)"
)
::change to manual if you still want to be able to use these manually without the services autorunning on boot. change to disabled if under no circumstances should they start (unless reenabled). use sc delete %%p if they should be wiped from registry (unusable)
::if you dont use a microsoft account to sign in, uncomment the below line
::reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc" /v Start /t REG_DWORD /d 4 /f
::protected services to include later: DPS, WdiSystemHost, WdiServiceHost
set quenchlist=DiagTrack TapiSrv dwappushservice DsSvc WbioSrvc diagnosticshub.standardcollector.service RemoteRegistry lfsvc diagsvc DispBrokerDesktopSvc
for %%q in (%quenchlist%) do (
sc stop %%q >NUL
::reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%%q" /v Start /t REG_DWORD /d 4 /f
sc config %%q start= disabled
echo "Service %%q changed to disabled"
)

::break > %systemroot%\DiagTrack\analyticsevents.dat 

::TermService, UmRdpService, and SessionEnv is for remote desktop. DusmSvc is for metered networks (mostly), DPS is diagnostic policy service.
::sc delete TabletInputService && sc delete TermService && sc delete UmRdpService && sc delete DPS && sc delete DusmSvc
::if you DO NOT need bluetooth:
::sc delete BTAGService && && sc stop BthAvctpService && sc delete BthAvctpService && sc stop bthserv && sc delete bthserv
::if you DO NOT EVER need to print anything
::sc stop Spooler && sc delete Spooler


cd %~dp0
REM More servers found to be ms telemetry posted on my github. I originally found these either by RevEng tools and scattered across the internet. I just formatted them and gave them the prefix "0.0.0.0 "
if not exist "ms_telemetry_list.txt" (curl https://raw.githubusercontent.com/InquireWithin/W10BSRemover/main/ms_telemetry_list.txt > ms_telemetry_list.txt)
type ms_telemetry_list.txt > %SystemRoot%\System32\drivers\etc\hosts

echo "start of reg key edit"
echo "breaking down windows defender..."

::WIP
::"$currentuser = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
::powershell -Command "&{"^
:: "$userformat = "$([System.Environment]::Username)\\$([System.Environment]::UserDomainName);"^
:: "$targetkey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows Defender');"^
 
 
:: "$acl = (get-acl 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender');"^
:: "$whogoesthere = (whoami);"^
 ::"$idref = [System.Security.Principal.NTAccount]'Administrators';"^
 ::"$regperms = [System.Security.AccessControl.RegistryRights]::FullControl;"^
 ::"$actype = [System.Security.AccessControl.AccessControlType]::Allow;"^
 ::"$propfl = [System.Security.AccessControl.PropagationFlags]::None;"^
 ::"$inhfl = [System.Security.AccessControl.InheritanceFlags]::None;"^
 ::"$regrule = New-Object System.Security.AccessControl.RegistryAccessRule ($idref, $actype, $regperms, $inhfl, $propfl, [bool]0);"^
 ::"$acl.AddAccessRule($regrule);"^
 ::"$acl | Set-Acl 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender';"^
 ::"}"
 
 

::Update: Somewhere along the line of build 1903 this (allegedly) stopped being effective. leaving it here for users on older ISOs. Can only be changed now by messing around w/ ACE's and ACL's
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
::This should work for modern ms defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 0 /f
:: Remove Definition Updates
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates\DefinitionUpdateFileSharesSources" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontReportInfectionInformation /t REG_DWORD /d 0 /f

echo "disabling auto-updates (pt1)"
::For Windows Server 2016 (with Server Core or Desktop Experience): Disable auto-updates (this came from ms docs themselves). Afterwards go to Windows Settings -> Security Settings -> Public Key Policies -> Certificate Path Validation Settings -> Network Retrieval -> Define these policy settings.
::Also uncheck the "Automatically update certificates in the Microsoft Root Certificate Program (recommended)" box. Do these things alongside the reg add.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot /v DisableRootAutoUpdate /t REG_DWORD /d 1 /f

::sometimes spyware applications will dump things here. clean it up so it wont be able to revisit the info.
::del /s /q "%windir%\tracing\*"
::this is meant to be a 'service' that will show the system health of your machine, but something like this DOES NOT need to start on login, you likely didnt even know it existed.
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth" /f
::Microsoft is so inconceivably greedy and lustful for data that they've implemented telemtetry in the clipboard. Modern computing horrors beyond by comprehension.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Clipboard" /v IsClipboardSignalProducingFeatureAvailable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Clipboard" /v IsCloudAndHistoryFeatureAvailable /t REG_DWORD /d 0 /f
::ApplicationFrameHost.exe is active whenever one or more Microsoft || Windows Store apps is running. If this instance is cancelled, it should also cause those unspecified apps to close.
::taskkill /f /im ApplicationFrameHost.exe
::Spyware
echo "Removing explorer-related junk"
::protected key
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Personalization" /v AllowPersonalization /t REG_DWORD /d 0 /f
::recent doc history is inconsistent (obviously) and clutters up explorer
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsHistory /t REG_DWORD /d 1 /f
:: reg key responsible for automatically running a scan on your system to upload to microsoft's remote servers
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v EnabledExecution /t REG_DWORD /d 0 /f
:: edge sometimes gets used by default (even in cURL (curl) command) so I'm ensuring it doesnt send certain usage stats
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Edge" /v UsageStatsInSample /t REG_DWORD /d 0 /f
::shouldnt make a difference anyway but if start menu returns, it'll help
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SVDEn /v PromoteOEMTiles /t REG_DWORD /d 0 /f

echo "negating cloudstore keys"
::CloudStore

::protected key
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\SystemMetaData /v CloudStorePlatformSupported /t REG_DWORD /d 0 /f

reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\SystemMetaData /v HasCuratedTileCollectionsInitialized /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\StoreInit /v HasStoreCacheInitialized /t REG_DWORD /d 0 /f

::only works on x86 systems and later windows versions
::reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackageDetect\Microsoft-OneCore-EventLogAPI-Package~31bf3856ad364e35~amd64~~0.0.0.0 /v Microsoft-OneCore-DeviceUpdateCenter-Package~31bf3856ad364e35~amd64~en-US~10.0.19041.1202 /t REG_DWORD /d 0 /f

::risky ms edge key, protected by default
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\MicrosoftEdge /v OSIntegrationLevel /t REG_DWORD /d 0 /f

::I dont use Find My Device on windows but if you do (why), comment this next line out or delete it
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice /v AllowFindMyDevice /t REG_DWORD /d 0 /f

::Remote fonts are not only bloat with a garbage premise, its also proprietary bloat just like this whole OS.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System /v EnableFontProviders /t REG_DWORD /d 0 /f

::Windows Insider preview builds are not needed. One of the script's intents is to *prevent* updating the system and *prevent* MS from forcing new features and reversions of your changes.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds /v AllowBuildPreview /t REG_DWORD /d 0 /f
echo "Configuring IE"
::They even tarnished internet explorer before tossing it by the wayside. Shame.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer" /v AllowServicePoweredQSA /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" /v PolicyDisableGeolocation /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v AutoSuggest /t REG_SZ /d "no" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /t REG_DWORD /d 0 /f
::do note that this line below makes your Internet Explorer possibly less secure, however if you're using IE in %CURRENT_YEAR% you arent using it for security. If you are, (why), delete the line below.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f

::also big thanks to ChrisTitusTech's w10script for getting rid of a headache that comes with dual booting in one line (time inconsistency)
reg add HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation /v RealTimeIsUniversal /t REG_DWORD /d 0 /f

:: Content Delivery is tough to remove once you've already booted the iso live and made a user account, hopefully these keys should help negate its prevalence.
:: Most effective if ran before a user account is created.
echo "nuke the content delivery here"
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f 
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent /f 

::remove auto update of offline maps
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps /v AutoDownloadAndUpdateMapData /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps /v AllowUntriggeredNetworkTrafficOnSettingsPage /t REG_DWORD /d 0 /f

::disable news feeds
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f

::Disable storage health
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageHealth /v AllowDiskHealthModelUpdates /t REG_DWORD /d 0 /f 

::Disable Teredo
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition /v Teredo_State /t REG_SZ /d Disabled /f

::disable network status indicator (it will ping remote servers and tell the servers if you have network connection and what your active topology looks like)
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator /v NoActiveProbe /t REG_DWORD /d 1 /f

::turn off location storage and collection
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location /v Value /t REG_SZ /d "Deny" /f
reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors /v DisableLocation /t REG_DWORD /d 1 /f 
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy /v LetAppsAccessLocation /t REG_DWORD /d 0 /f

::turn off speech related functions for winapps
reg add HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy /v HasAccepted /t REG_DWORD /d 0 /f 
reg add HKLM\SOFTWARE\Policies\Microsoft\Speech /v AllowSpeechModelUpdate /t REG_DWORD /d 0 /f

::turn off logging of user activity (presumably non-idle uptime hours)
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v EnableActivityFeed /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v PublishUserActivities /t REG_DWORD /d 0 /f 
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v UploadUserActivities /t REG_DWORD /d 0 /f

::nuke MS Store (again)
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsStore /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsStore /v AutoDownload /t REG_DWORD /d 2 /f

::nuke Delivery Optimization (again)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DelveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f

::nuke automatic windows update (again)
reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer /t REG_SZ /d " " /f
reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUStatusServer /t REG_SZ /d " " /f
reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v UpdateServiceUrlAlternate /t REG_SZ /d " " /f
reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer /t REG_DWORD /d 1 /f
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate /v AutoDownload /t REG_DWORD /d 5 /f
::nuke telemetry auto-configuring itself
reg add HKLM\Software\Policies\Microsoft\Windows\DataCollection /v DisableOneSettingsDownloads /t REG_DWORD /d 1 /f

::Remove Widgets
reg add HKLM\Software\Policies\Microsoft\Windows\Widgets /v AllowWidgets /t REG_DWORD /d 0 /f

@rem *** Remove Misc Telemetry & Data Collection ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Start_TrackProgs /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Siuf\Rules /v PeriodInNanoSeconds /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Siuf\Rules /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add HKCU\SOFTWARE\Microsoft\InputPersonalization /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add HKCU\SOFTWARE\Microsoft\InputPersonalization /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableCloudOptimizedContent /t REG_DWORD /d 1 /f

@REM Settings -> Privacy -> General -> Let apps use my advertising ID...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
REM - SmartScreen Filter: Disable
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v ConfigureAppInstallControlEnabled /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v ConfigureAppInstallControl /t REG_SZ /d Anywhere /f

REM - Let websites access your language settings
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f

@REM WiFi Sense: HotSpot Sharing: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
@REM WiFi Sense: Shared HotSpot Auto-Connect: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f

:: block OEM connections by the network manager
reg add HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f 

@REM Change Windows Updates to "Notify to schedule restart"
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v UxOption /t REG_DWORD /d 1 /f
@REM Disable P2P Update downlods outside of local network
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 99 /f

@REM *** Disable Cortana (again) ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f

REM *** Hide the search box from taskbar. You can still search by pressing the Win key and start typing what you're looking for ***
REM 0 = hide completely, 1 = show only icon, 2 = show long search box
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

REM *** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

REM *** Set Windows Explorer to start on This PC instead of Quick Access ***
REM 1 = This PC, 2 = Quick access
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

REM *** Disable Suggestions in the Start Menu ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f

:: shut off gamebar (fix ms-overlay issue) pt 2
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v HistoricalCaptureEnabled /t REG_DWORD /d 0 /f

::ensure diagtrack has a much harder time if it spawns back
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack /v ShowedToastAtLevel /t REG_DWORD /d 0 /f

::pre-installed / pre-provisioned application reg key cleanup. These keys were found in Sycnex's W10Debloater script. I re-implemented them in batch and categorized them.
set provisionedregkeysbt=46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy
(for %%p in (%provisionedregkeysbt%) do (reg delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\%%p" /f))
reg delete "HKCR\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f
reg delete "HKCR\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" /f
reg delete "HKCR\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f
set provisionedregkeyslaunch=46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy
(for %%p in (%provisionedregkeyslaunch%) do (reg delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\%%p" /f))
set provisionedregkeyspid=ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy
(for %%p in (%provisionedregkeyspid%) do (reg delete "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\%%p" /f))


::if you must use ms edge at some point (or already have used it frequently), you should comment the following lines, as I wont test whether this breaks edge or not.
if exist "C:\Users\%trueuser%\AppData\Local\Microsoft\Edge\User Data\" (
cd /d "C:\Users\%trueuser%\AppData\Local\Microsoft\Edge\User Data\"
del /s /q *.*
cd %~dp0
)


::src of the following lines: https://www.wintips.org/how-to-access-windowsapps-folder-windows-10-8/#part-2
::Will not work if the files are encrypted, which is why I suggest removing the bitlocker encryption that comes default w/ Windows
::Seems to mostly be deprecated and patched out though as this folder is System level access. Keep here for older ISO's to use
::takeown /F "%ProgramFiles%\WindowsApps"
::takeown /F "%ProgramFiles%\WindowsApps" /r /d y
::icacls "%ProgramFiles%\WindowsApps" /grant Administrators:F
::icacls "%ProgramFiles%\WindowsApps\*" /grant Administrators:F /t
::icacls "%ProgramFiles%\WindowsApps" /setowner "NT Service\TrustedInstaller"
::del /s /q "%ProgramFiles%\WindowsApps"
:: These lines above should give the current user full access and control over the C:\ProgramFiles\WindowsApps folder (where NonRemovable packages are provisioned for all users)
::Local user provisioned package and win store data files are in C:\Users\%username%\AppData\Local\Packages

::only deletes locally, not system wide
::del /s /q "C:\Users\%trueuser%\AppData\Local\Packages\*"
::del /s /q "C:\Users\%trueuser%\AppData\Local\Package Cache\*"
::del /s /q "C:\Users\%trueuser%\AppData\Local\OneDrive"
del /s /q "C:\Users\%trueuser%\AppData\Local\GameAnalytics"

::delete live kernel log(s), freed up 1.51 GB for me
if exist "C:\Windows\LiveKernelReports\*.dmp" (
cd /d C:\Windows\LiveKernelReports
del /s /q *.dmp
rd /s /q %systemdrive%\$Recycle.bin
cd %~dp0
)



::firewall rules to hopefully prevent some specific applications from ever sending spyware data if other containment methods fail
::TIL the only reason "Control Panel" was replaced by "Settings" was to implement telemetry in it. Wonderful.
::protocol = any by default
echo "adding a few firewall rules..."
netsh.exe advfirewall firewall add rule name="ICP" program="C:\Windows\ImmersiveControlPanel\SystemSettings.exe" dir=out enable=yes action=block profile=any >NUL
netsh.exe advfirewall firewall add rule name="AADBroker" program="C:\Windows\SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\Microsoft.AAD.BrokerPlugin.exe" dir=out enable=yes action=block profile=any >NUL
netsh.exe advfirewall firewall add rule name="ATS" program="C:\Windows\SystemApps\Microsoft.AsyncTextService_8wekyb3d8bbwe\Microsoft.AsyncTextService.exe" dir=out enable=yes action=block profile=any >NUL
netsh.exe advfirewall firewall add rule name="BEH" program="C:\Windows\SystemApps\Microsoft.BioEnrollment_cw5n1h2txyewy\BioEnrollmentHost.exe" dir=out enable=yes action=block profile=any >NUL
netsh.exe advfirewall firewall add rule name="EC" program="C:\Windows\SystemApps\Microsoft.ECApp_8wekyb3d8bbwe\Microsoft.ECApp.exe" dir=out enable=yes action=block profile=any >NUL
netsh.exe advfirewall firewall add rule name="ASF" program="C:\Windows\SystemApps\Microsoft.Windows.AddSuggestedFoldersToLibraryDialog_cw5n1h2txyewy\AddSuggestedFoldersToLibraryDialog.exe" dir=out enable=yes action=block profile=any >NUL
netsh.exe advfirewall firewall add rule name="FE" program="C:\Windows\SystemApps\Microsoft.Windows.FileExplorer_cw5n1h2txyewy\FileExplorer.exe" dir=out enable=yes action=block profile=any >NUL
:: format: netsh.exe advfirewall firewall add rule name="" program="" dir=out enable=yes action=block profile=any
::disallow any outbound connections from cortana (this shouldve already been implemented by now. But, as you should know, sometimes these changes revert, so its always good to have a second line of defense
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{0DE40C8E-C126-4A27-9371-A27DAB1039F7}" /t REG_SZ /d "v2.25|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe|Name=Block outbound Cortana|" /f >NUL



::rename this file so that the reg key accessing it for configuration information is lost. Best practice is to delete that regkey as well. (might be patched, testing)
::move "C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\default.html" "C:\Windows\SystemApps\Microsoft.Windows.Clo:udExperienceHost_cw5n1h2txyewy\RemovedBS.html"

::Only if you have another photo viewer
::reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\FilePicker\Config\StartLocation" /v PicturesLibrary /f
::All packages on the system and their info can be noted with Get-AppxPackage -allusers (in powershell admin mode) or Powershell -Command "Get-AppxPackage -allusers" in cmd admin

echo "Removing default apps..."
powershell -Command "Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online"
@rem Remove Apps
PowerShell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Cortana* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *GetStarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Messaging* | Remove-AppxPackage"
::powershell -Command "Get-AppxPackage *EventProvider* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Microsoft-WindowsPhone* | Remove-AppxPackage"
powershell -Command "Delete-DeliveryOptimizationCache" -Force
powershell -Command "Disable-AppBackgroundTaskDiagnosticLog"
powershell -Command "Disable-WindowsErrorReporting"
:: fix to the ms-gamingoverlay issue (turning off gamebar) pt 1
powershell -Command "get-appxpackage *XboxGamingOverlay* | remove-appxpackage"
powershell -Command "get-appxpackage *XboxGameOverlay* | remove-appxpackage"
powershell -Command "get-appxpackage *Wallet* | remove-appxpackage"
powershell -Command "get-appxpackage *GetHelp* | remove-appxpackage"
powershell -Command "get-appxpackage *MixedReality.Portal* | remove-appxpackage"
powershell -Command "get-appxpackage *WindowsFeedbackHub* | Remove-AppxPackage"
powershell -Command "get-appxpackage Microsoft.MicrosoftSolitaireCollection| remove-appxpackage"
powershell -Command "get-appxpackage Microsoft.MicrosoftEdge.Stable | remove-appxpackage"
echo "Non-provisioned default apps successfully removed"
::powershell -Command "" 



echo "Configuring scheduled tasks..."
REM *** SCHEDULED TASKS tweaks ***
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

::Optional and more 'arcane' removals
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


::the following are (mostly) background processes that do nothing but consume processing power and memory
::consider the same for the WindowsApps folder (%programfiles%\WindowsApps)

::backup for if the prior method of removing these didnt work (most likely will not unless you're on an older ISO)
:: The best way to do this is actually to do these manually in explorer or in their own script, which have a higher degree of consistency. There's also a couple of odd bugs associated w/ these
::for best results, run these in a separate batch file. Though be careful! These operations can cause some breakage!
::the purpose of this is to prevent the programs from even running, as removal is too cumbersome, and as a safety net for potential internal code to override firewall rules
goto next

::another alternative is restricting SYSTEM from accessing these folders using icacls
::these commands are highly dangerous, skipping by default
set winapps = %windir%\SystemApps

taskkill /f /im ShellExperienceHost.exe
move C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy.bak

::I still recommend leaving search on if needed so this is commented. This script (with the below lines commented) still allows for spawning a search bar with windows key + s
::taskkill /f /im SearchApp.exe
::move C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy.bak

taskkill /f /im SecurityHealthService.exe && taskkill /f /im SecurityHealthSystray.exe
move C:\Windows\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy.bak


move %winapps%\Microsoft.AsyncTextService_8wekyb3d8bbwe %winapps%\Microsoft.AsyncTextService_8wekyb3d8bbwe.bak
move %winapps%\Microsoft.BioEnrollment_cw5n1h2txyewy %winapps%\Microsoft.BioEnrollment_cw5n1h2txyewy.bak
move %winapps%\microsoft.creddialoghost_cw5n1h2txyewy %winapps%\microsoft.creddialoghost_cw5n1h2txyewy.bak
::eye control
move %winapps%\Microsoft.ECApp_8wekyb3d8bbwe %winapps%\Microsoft.ECApp_8wekyb3d8bbwe.bak

::move %winapps%\Microsoft.MicrosoftEdge_8wekyb3d8bbwe %winapps%\Microsoft.MicrosoftEdge_8wekyb3d8bbwe.bak
move %winapps%\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe %winapps%\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe.bak
move %winapps%\Microsoft.Win32WebViewHost_cw5n1h2txyewy %winapps%\Microsoft.Win32WebViewHost_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.AddSuggestedFoldersToLibraryDialog_cw5n1h2txyewy %winapps%\Microsoft.Windows.AddSuggestedFoldersToLibraryDialog_cw5n1h2txyewy.bak
::move %winapps%\Microsoft.Windows.AppRep.ChxApp_cw5n1h2txyewy %winapps%\Microsoft.Windows.AppRep.ChxApp_cw5n1h2txyewy.bak
::move %winapps%\Microsoft.Windows.AppResolverUX_cw5n1h2txyewy %winapps%\Microsoft.Windows.AppResolverUX_cw5n1h2txyewy.bak
::move %winapps%\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy %winapps%\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy %winapps%\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy %winapps%\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy.bak
::shouldnt be needed due to explorer.exe already existing, might have to kill explorer.exe first
::move %winapps%\Microsoft.Windows.FileExplorer_cw5n1h2txyewy %winapps%\Microsoft.Windows.FileExplorer_cw5n1h2txyewy.bak
move %winapps%\microsoft.windows.narratorquickstart_8wekyb3d8bbwe %winapps%\microsoft.windows.narratorquickstart_8wekyb3d8bbwe.bak
::move %winapps%\Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy %winapps%\Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy.bak
::move %winapps%\Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy %winapps%\Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy.bak
::can cause a taskbar freeze
::taskkill /f /im StartMenuExperienceHost.exe && move C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\ParentalControls_cw5n1h2txyewy C:\Windows\SystemApps\ParentalControls_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Windows.CBSPreview_cw5n1h2txyewy C:\Windows\SystemApps\Windows.CBSPreview_cw5n1h2txyewy.bak

:next

echo "Tweaking explorer configuration..."
@rem NOW JUST SOME TWEAKS
REM *** Show hidden files in Explorer ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
 
REM *** Show super hidden system files in Explorer ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

REM *** Show file extensions in Explorer ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f

:: Translucent taskbar
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v UseOLEDTaskbarTransparency /t REG_DWORD /d 1 /f
echo "Explorer has been configured successfully"

REM *** Uninstall OneDrive ***
echo "Starting uninstall of OneDrive..."
start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
rd C:\OneDriveTemp /Q /S >NUL 2>&1
rd "%USERPROFILE%\OneDrive" /Q /S >NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S >NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S >NUL 2>&1
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
echo OneDrive has been removed. Windows Explorer needs to be restarted.
pause
start /wait TASKKILL /F /IM explorer.exe
start explorer.exe
ipconfig /flushdns
exit
