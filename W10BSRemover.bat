:: 14/4/22 LB

::If this file was flagged a security risk, know that this is why: https://www.bleepingcomputer.com/news/microsoft/windows-10-hosts-file-blocking-telemetry-is-now-flagged-as-a-risk/

::NOTE: This script ASSUMES your registry key:
::HKEY_LOCAL_MACHINES\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath
::is set to
::%SystemRoot%\System32\drivers\etc
::the file that will be edited is %SystemRoot%\System32\drivers\etc
::by default %SystemRoot% is C:\Windows

::There is also a proprietary software option for this (OOSU10) that ofc I can't include b/c proprietary.
::Implement DWS (Destroy Windows 10 Spying) if possible. If not, use manually from here (https://github.com/spinda/Destroy-Windows-10-Spying) <- Forked version
:: If I do, include the apache license alongside it (https://www.apache.org/licenses/LICENSE-2.0) as it is licensed under Apache.
:: The original repo for DWS was deleted, and most forks are read only archives now. 
:: Another fork (https://github.com/Wohlstand/Destroy-Windows-10-Spying)

::Another option instead of going through this confusing rigamarole is using Windows 10 Enterprise LTSB. Though I don't know if AutoKMS or W10DigitalActivator work on it.

::Recommendations that I wont/cant script here that will stengthen your control in the war against the operating system and/or its components.
::create a "super admin" account so you can maximize control over what you do with your system and what runs on it.
::If you use a microsoft acc to sign in, change to a local account
::Request data deletions locally via settings (probably in account privacy or protection), and from the microsoft account panel via browser if you were/are using MS account to log on
::Download Process Explorer, and replace taskmanager with it. (launch any instance of it, or the native task manager with: super + r -> "taskmgr" -> enter)
::Download autoruns to see hidden/arcane scheduled tasks you can curate and manually kill to your liking. ProcExp (Process Explorer) also helps with this.
::go into windows security settings and turn off "tamper prevention" (as it prevents you from changing things around, not malware), turn of all cloud-based "features" as well
::Turn off internet connection whenever you dont actively need it or wont be using it for the next twenty or so minutes at least
::Remove automatic internet connection on launch, this may be only an option via your network engine, it will also help w/ above
::Make sure to check services.msc for some other problematic services (like KillerAnalyticsService for users w/ Killer network drivers)
::If you have javs on your system, reduce some bandwith by killing (and preventing from starting up on login) the services: jucheck.exe and jusched.exe
::Use the ublock origin domain blocker list, it can be found in the "resources" repo of my github @ https://github.com/InquireWithin/resources/blob/main/ublock_adblock_server_filter.txt
:: ^ copy and paste this into your hosts file (C:\Windows\System32\drivers\etc\hosts) and save. Some websites will say you have an adblocker though, so you can save a backup of the hosts file, clear the hosts file, do whatever, then put the addresses back
::I cant write any code that would globally stop applications from stealing focus without your permission or content, which renders >1 monitor setups useless.
::Microsoft refuses to fix this. The best you can do is use tools like autoruns to find the offender, and kill/delete/configure the software.
::use an older ISO image, self explanatory. You won't get it from Microsoft so don't go looking there.
::Remove bitlocker encryption. Don't just delete random files it relies on though, you want to properly uninstall this one or your files might be locked up forever. This schema prevents you from accessing certain system folders or elements.
::RUN THIS BEFORE A NEW USER ACCOUNT IS CREATED, and DISM an iso before it is live to deprovision packages.
::If you bought a laptop or a prebuilt desktop from any OEM (Dell, Hp, lenovo, asus, etc) and you did NOT reinstall the OS, do so, because the OEM has system level spyware as well and I don't want to cover that here.
@echo off

::SELF ELEVATION SEQUENCE (UAC PROMPT)
goto init
:init
 setlocal DisableDelayedExpansion
 set cmdInvoke=1
 set winSysFolder=System32
 set "batchPath=%~dpnx0"
 rem this works also from cmd shell, other than %~0
 for %%k in (%0) do set batchName=%%~nk
 set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
 setlocal EnableDelayedExpansion
 goto checkPrivileges

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
REM Creating a Newline variable (the two blank lines are required!) here in case I use it
set NLM=^
set NL=^^^%NLM%%NLM%^%NLM%%NLM%
REM set keys to input for the user in non-automatable cases later on
set SendKeys=CScript //nologo //E:JScript "%~F0"
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

::TODO: check keys in Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Edge\
::TODO: check if Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\MicrosoftEdge OSIntegrationLevel can be set to 0.
::TODO: Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Cortana toggle to 0
::TODO: Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore check
::Analyze C:\Windows\DiagTrack\ It reveals some more services and possible reg keys to block within its files
::TODO: Add different 'tiers' of the preconfiguration based on how many features and services it removes\
::https://serverfault.com/questions/653814/windows-firewall-netsh-block-all-ips-from-a-text-file
::Also make a reversal script

::set to the position of the command line arguments if present
SETLOCAL ENABLEDELAYEDEXPANSION
set /A LOGV=0
set /A STARTUP=0
::there was another var set here
::if command line argument 1 or 2 is "-l" "-s" do as follows (-l is log the output, -s is run this script at startup)
if /i "%~1" == "-l" set /A LOGV=1
if /i "%~2" == "-l" set /A LOGV=2

if /i "%~1" == "-s" do (
set /A STARTUP=1
echo setting startup to 1
goto startup
)
if /i "%~2" == "-s" do (
set /A STARTUP=2
echo setting startup to 2
goto startup
)
if %STARTUP% = 0 do (
echo STARTUP=0
goto log
)

:startup
 echo Startup Func Here. STARTUP=%STARTUP%
 ::check or query the reg key first before doing add, set can be used if already, serviceless option, less permissions
 ::reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WTenBSRemover" /t REG_SZ /d %~0 /f
 ::service option, more permissions
 sc create "W10BSRemover" start= delayed-auto displayname= "W10BSRemover" binpath= %~dpnx0
 ::third option is creating a scheduled task
 goto log


::this will remove output from terminal unfortunately, I'd probably need WinTee or something to stop this
:log
 echo Log Func Here. LOGV=%LOGV%
 IF %LOGV% EQU 1 call :one > W10BSRemover_LOG.txt
 IF %LOGV% EQU 2 call :one > W10BSRemover_LOG.txt
 goto one


::"main" function
:one
echo %LOGV%
echo %STARTUP%
echo %~dp0
echo %~nx0
echo %~0
::Back up and flush current hosts file and start
type %SystemRoot%\System32\drivers\etc\hosts > %SystemRoot%\System32\drivers\etc\hosts-BACKUP
::back up the windows store access control lists, stored in %SystemRoot%\System32
icacls "%ProgramFiles%\WindowsApps" /save WindowsApps.acl
:: if a serious error occurs w/ this use: icacls "%ProgramFiles%" /restore WindowsApps.acl

:: break>%SystemRoot%\System32\drivers\etc\hosts :: Use this if testing/debugging 
::Complete spyware, no utility gained from these
sc delete DiagTrack && sc delete dmwappushservice
::Windows update service
sc delete UsoSvc
::Remove biometrics service
sc delete WbioSrvc
::Try to delete WaaSMedicSvc at some point, its protected by windows "super super user"
::The timezone autoupdate service relies on constant pinging of remote servers and geolocation. Manually set it in settings.
sc delete tzautoupdate
::geolocation service
sc delete lfsvc
::Spot Verifier. Claims to detect system corruption but if found will just cause errors. I'd rather use my "corrupt" system (by windows definitions)
sc delete svsvc
::bloat. if you're running this script you're not running windows insider, and if you are (for some ungodly reason) remove this line
sc delete wisvc
::the fact that theyve implemented spyware and massive bloat (cortana) into a literal search bar is beyond me.
::Don't worry though, the taskbar looks far better without it, and it can still be accessed via super + s
sc delete WSearch

::open autorun soon and check all the different automatically configured services and remove the spyware-oriented ones

::route these selected spyware servers to 0.0.0.0 in routing table (can not be accessed)
route ADD 131.253.14.0 MASK 255.255.255.0 0.0.0.0
route ADD 65.52.100.0 MASK 255.255.255.0 0.0.0.0
route ADD 65.4.54.0 MASK 255.255.255.0 0.0.0.0
route ADD 65.55.194.0 MASK 255.255.255.0 0.0.0.0
route ADD 93.184.215.0 MASK 255.255.255.0 0.0.0.0
route ADD 134.170.115.0 MASK 255.255.255.0 0.0.0.0
route ADD 65.55.252.0 MASK 255.255.255.0 0.0.0.0

REM More servers found to be ms telemetry posted on my github. I originally found these either by RevEng tools and scattered across the internet. I just formatted them and gave them the prefix "0.0.0.0 "
if not exist ms_telemetry_list.txt (curl https://github.com/InquireWithin/W10BSRemover/blob/main/ms_telemetry_list.txt > ms_telemetry_list.txt)
type ms_telemetry_list.txt > %SystemRoot%\System32\drivers\etc\hosts


::Intel has a service specifically to act as a "guard" for other software. This is just a way to protect bloated applications runstate. commented until tested, there are more dirs w/ this svc exec in them in the parent dir
::set intelswprotect1 = C:\Windows\System32\DriverStore\FileRepository\sgx_psw.inf_amd64_fafb1d329fdfe2c6
::if exist %intelswprotect1%\aesm_service.exe do del /s /q %intelswprotect1%\aesm_service.exe

::If you have KillerAnalyticsService (Spyware service from Killer network driver from Rivet Networks) currently running, kill it and ensure it doesnt autostart. Sometimes this doesnt work however.
::Yes this isnt directly Windows 10 related but many OEM W10 laptops have this driver and its respective packet sniffer running.
if exist C:\Windows\System32\drivers\RivetNetworks\Killer\KillerNetworkService.exe do (
taskkill /f /im KillerAnalyticsService.exe
::Killer's driver itself is often a disguised file, at least in part. watch for "oemXXX" with XXX being numeric. Sometimes only has two digits. My two instances are "oem149.inf" and "oem90.inf"
::Will try to kill autostart of the analytics ONLY without killing internet connection. Luckily this is made simpler due to it being a separate engine.
reg add "HKLM\System\CurrentControlSet\Services\Killer Analytics Service" /v "Start" /t REG_DWORD /d 0 /f
:: above line uncommented b/c below line does not always complete the task
del /s /q "C:\Program Files\Killer Networking\Killer Control Center\KillerAnalyticsService.exe"
)
    


::DISABLING WINDOWS ANTIVIRUS PERMANENTLY (at least until you revert the regkey value to 0, or delete it)
::I consider this bloat and malware as the user has no ability even to turn it off, it will automatically turn itself back on. Even when it is off, it still performs random tasks and refuses certain tasks.
::The best anti-malware is common sense. Comment this line out if you still want Windows Defender on.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

::no need for reversing as these 4 lines have no harm
::sometimes spyware applications will dump things here. clean it up so it wont be able to revisit the info.
del /s /q "%windir%\tracing\*"
::this is meant to be a 'service' that will show the system health of your machine, but something like this DOES NOT need to start on login, you likely didnt even know it existed.
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth" /f
::Microsoft is so inconceivably greedy and lustful for data that they've implemented telemtetry in the clipboard. Modern computing horrors beyond by comprehension.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Clipboard" /v IsClipboardSignalProducingFeatureAvailable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Clipboard" /v IsCloudAndHistoryFeatureAvailable /t REG_DWORD /d 0 /f
::ApplicationFrameHost.exe is active whenever one or more Microsoft || Windows Store apps is running. If this instance is cancelled, it should also cause those unspecified apps to close.
taskkill /f /im ApplicationFrameHost.exe
::Spyware
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Personalization" /v AllowPersonalization /t REG_DWORD /d 0 /f
::recent doc history is inconsistent (obviously) and clutters up explorer
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsHistory /t REG_DWORD /d 1 /f
:: reg key responsible for automatically running a scan on your system to upload to microsoft's remote servers
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v EnabledExecution /t REG_DWORD /d 0 /f
:: edge sometimes gets used by default so I'm ensuring it doesnt send certain usage stats
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Edge" /v UsageStatsInSample /t REG_DWORD /d 0 /f
::shouldnt make a difference anyway but if start menu returns, it'll help
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SVDEn /v PromoteOEMTiles /t REG_DWORD /d 0 /f


::DISM commands. I think of DISM as Disk Image System Management, its a tool that will modify a disk image.
::option "-Online" means I am targeting a currently running disk image, the one you're running the script on.
::This is a proposed solution to the problem of non-removable pre-provisioned packages.
::Log path by default (can be changed by -LogPath) is %WINDIR%\Logs\Dism\dism.log
::found in Windows10Debloater.ps1
::Example:
::powershell -Command Remove-WindowsPackage -Online -NoRestart -PackageName "windows.immersivecontrolpanel_10.0.2.1000_neutral_neutral_cw5n1h2txyewy" -Force

::UPDATE: Microsoft has crudely forced this out of relevance due to returning an invalid paramter error when a package with "NonRemovable" set to true is specified. How much lower can they get?

::20/5/22 best thing I can try to do now is attempt to set NonRemovable values to 0 and then deprovision them in the PS script or try to match permissions
::src of the following lines: https://www.wintips.org/how-to-access-windowsapps-folder-windows-10-8/#part-2
::Will not work if the files are encrypted, which is why I suggest removing the bitlocker encryption that comes default w/ Windows
::Seems to mostly be deprecated and patched out though as this folder is System level access.
takeown /F "%ProgramFiles%\WindowsApps"
takeown /F "%ProgramFiles%\WindowsApps" /r /d y
icacls "%ProgramFiles%\WindowsApps" /grant Administrators:F
icacls "%ProgramFiles%\WindowsApps\*" /grant Administrators:F /t
icacls "%ProgramFiles%\WindowsApps" /setowner "NT Service\TrustedInstaller"
:: These lines above should give the current user full access and control over the C:\ProgramFiles\WindowsApps folder (where NonRemovable packages are provisioned for all users)
::Local user provisioned package and win store data files are in C:\Users\%username%\AppData\Local\Packages
del /s /q "%ProgramFiles%\WindowsApps"

::leave uncommented if running as a normal user or admin privleges from regular user account
del /s /q "C:\Users\%username%\AppData\Local\Packages\*"
del /s /q "C:\Users\%username%\AppData\Local\Package Cache\*"
del /s /q "C:\Users\%username%\AppData\Local\OneDrive"
del /s /q "C:\Users\%username%\AppData\Local\GameAnalytics"
rd /s /q %systemdrive%\$Recycle.bin


::Only if you have another photo viewer
::reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\FilePicker\Config\StartLocation" /v PicturesLibrary /f
::All packages on the system and their info can be noted with Get-AppxPackage -allusers (in powershell admin mode) or Powershell -Command "Get-AppxPackage -allusers" in cmd admin
powershell -Command "Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online"
powershell -Command "Get-AppxPackage -Name *EventProvider* | Remove-AppxPackage -AllUsers"
powershell -Command "Delete-DeliveryOptimizationCache" -Force
powershell -Command "Disable-AppBackgroundTaskDiagnosticLog"
powershell -Command "Disable-WindowsErrorReporting"
::powershell -Command "Get-AppxPackage -Name *Microsoft-WindowsPhone* | Remove-AppxPackage -AllUsers"




REM orig src: https://www.hwinfo.com/misc/RemoveW10Bloat.htm most of the following lines came from here
sc stop diagnosticshub.standardcollector.service
sc stop WMPNetworkSvc

sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config dmwappushservice start= disabled
sc config RemoteRegistry start= disabled
sc config TrkWks start= disabled
sc config WMPNetworkSvc start= disabled
sc config WSearch start= disabled
sc config SysMain start= disabled

REM *** SCHEDULED TASKS tweaks ***
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

::Optional and more 'arcane' removals, originally commented out in source script.
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
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable

REM *** Remove Cortana ***
REM Currently MS doesn't allow to uninstall Cortana using the above step claiming it's a required OS component (hah!)
REM We will have to rename the Cortana App folder (add ".bak" to its name), but this can be done only if Cortana is not running.
REM The issue is that when Cortana process (SearchUI) is killed, it respawns very quickly
REM So the following code needs to be quick (and it is) so we can manage to rename the folder
REM Disabling Cortana this way on Version 1703 (RS2) will render all items in the Start Menu unavailable.
REM I uncommented this regardless.
taskkill /F /IM SearchUI.exe
set winapps = %windir%\SystemApps
move "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy.bak"
:: The line above is a great workaround done at the link from src, I'll have some more attempts at it
move "%windir%\SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy" "%windir%\SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy.bak"
::background processes that do nothing but consume processing power and memory
::consider the same for the WindowsApps folder (%programfiles%\WindowsApps)
::https://www.tenforums.com/software-apps/158524-system-apps-list-purpose.html thread involving something similar to what i'm doing here

::backup for if the prior method of removing these didnt work (most likely will not unless you're on an older ISO)
if exist %ProgramFiles%\WindowsApps\ do (
taskkill /f /im ShellExperienceHost.exe
move C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy.bak

taskkill /f /im SearchApp.exe
move C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy

taskkill /f /im SecurityHealthService.exe
taskkill /f /im SecurityHealthSystray.exe
move C:\Windows\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy.bak


move %winapps%\Microsoft.LockApp_cw5n1h2txyewy %winapps%\Microsoft.LockApp_cw5n1h2txyewy.bak
move %winapps%\Microsoft.AsyncTextService_8wekyb3d8bbwe %winapps%\Microsoft.AsyncTextService_8wekyb3d8bbwe.bak
move %winapps%\Microsoft.BioEnrollment_cw5n1h2txyewy %winapps%\Microsoft.BioEnrollment_cw5n1h2txyewy.bak
move %winapps%\microsoft.creddialoghost_cw5n1h2txyewy %winapps%\microsoft.creddialoghost_cw5n1h2txyewy.bak
move %winapps%\Microsoft.ECApp_8wekyb3d8bbwe %winapps%\Microsoft.ECApp_8wekyb3d8bbwe.bak
move %winapps%\Microsoft.MicrosoftEdge_8wekyb3d8bbwe %winapps%\Microsoft.MicrosoftEdge_8wekyb3d8bbwe.bak
move %winapps%\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe %winapps%\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe.bak
move %winapps%\Microsoft.Win32WebViewHost_cw5n1h2txyewy %winapps%\Microsoft.Win32WebViewHost_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.AddSuggestedFoldersToLibraryDialog_cw5n1h2txyewy %winapps%\Microsoft.Windows.AddSuggestedFoldersToLibraryDialog_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.AppRep.ChxApp_cw5n1h2txyewy %winapps%\Microsoft.Windows.AppRep.ChxApp_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.AppResolverUX_cw5n1h2txyewy %winapps%\Microsoft.Windows.AppResolverUX_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy %winapps%\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.CapturePicker_cw5n1h2txyewy %winapps%\Microsoft.Windows.CapturePicker_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy %winapps%\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy %winapps%\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy.bak
::shouldnt be needed due to explorer.exe already existing
move %winapps%\Microsoft.Windows.FileExplorer_cw5n1h2txyewy %winapps%\Microsoft.Windows.FileExplorer_cw5n1h2txyewy.bak
move %winapps%\microsoft.windows.narratorquickstart_8wekyb3d8bbwe %winapps%\microsoft.windows.narratorquickstart_8wekyb3d8bbwe.bak
move %winapps%\Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy %winapps%\Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy.bak
move %winapps%\Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy %winapps%\Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy.bak
::move C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\ParentalControls_cw5n1h2txyewy C:\Windows\SystemApps\ParentalControls_cw5n1h2txyewy.bak
move C:\Windows\SystemApps\Windows.CBSPreview_cw5n1h2txyewy C:\Windows\SystemApps\Windows.CBSPreview_cw5n1h2txyewy.bak
)


@rem *** Remove Telemetry & Data Collection ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f

@REM Settings -> Privacy -> General -> Let apps use my advertising ID...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
REM - SmartScreen Filter for Store Apps: Disable
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
REM - Let websites provide locally...
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f

@REM WiFi Sense: HotSpot Sharing: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
@REM WiFi Sense: Shared HotSpot Auto-Connect: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f

@REM Change Windows Updates to "Notify to schedule restart"
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v UxOption /t REG_DWORD /d 1 /f
@REM Disable P2P Update downlods outside of local network
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f

@REM *** Disable Cortana & Telemetry ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

REM *** Hide the search box from taskbar. You can still search by pressing the Win key and start typing what you're looking for ***
REM 0 = hide completely, 1 = show only icon, 2 = show long search box
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

REM *** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

REM *** Set Windows Explorer to start on This PC instead of Quick Access ***
REM 1 = This PC, 2 = Quick access
REM reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

REM *** Disable Suggestions in the Start Menu ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f 

@rem Remove Apps
PowerShell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Cortana* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"

:: XboxGameCallableUI can no longer be removed this way. Slows execution massively when this error crops up.
::PowerShell -Command "Get-AppxPackage *xbox* | Remove-AppxPackage"

PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
::Commented due to not being able to be removed anymore via this method
::PowerShell -Command "Get-AppxProvisionedPackage *ContentDeliveryManager* | Remove-AppxProvisionedPackage"

@rem NOW JUST SOME TWEAKS
REM *** Show hidden files in Explorer ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
 
REM *** Show super hidden system files in Explorer ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

REM *** Show file extensions in Explorer ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f

REM *** Uninstall OneDrive ***
start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
rd C:\OneDriveTemp /Q /S >NUL 2>&1
rd "%USERPROFILE%\OneDrive" /Q /S >NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S >NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S >NUL 2>&1
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
echo OneDrive has been removed. Windows Explorer needs to be restarted.
::backslash needed in the former part so the "if exist" knows the input is a directory
if exist %userprofile%\Desktop\OneDriveBackupFiles\ do del /s /q %userprofile%\Desktop\OneDriveBackupFiles
pause
start /wait TASKKILL /F /IM explorer.exe
start explorer.exe
REM src end



:: Implement my modified version of w10debloater here
if not exist Windows10Debloater.ps1 (
curl https://raw.githubusercontent.com/InquireWithin/W10BSRemover/main/Windows10Debloater.ps1 > Windows10Debloater.ps1
)
::unstable due to provisioned packages issue, see readme section 6.
::Powershell.exe -Command "& {Start-Process Powershell.exe -ArgumentList '-ExecutionPolicy Bypass -File %~dp0Windows10Debloater.ps1' -Verb RunAs}"

ipconfig /flushdns
exit

