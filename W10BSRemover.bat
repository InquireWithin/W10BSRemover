:: 14/4/22 LB


::If this file was flagged a security risk, know that this is why: https://www.bleepingcomputer.com/news/microsoft/windows-10-hosts-file-blocking-telemetry-is-now-flagged-as-a-risk/

::Will probably add OEM-specific debloating and exception handling soon enough

::If this file was flagged a security risk, know that this is why: https://www.bleepingcomputer.com/news/microsoft/windows-10-hosts-file-blocking-telemetry-is-now-flagged-as-a-risk/

::NOTE: This script ASSUMES your registry key:
::HKEY_LOCAL_MACHINES\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath
::is set to
::%SystemRoot%\System32\drivers\etc
::the file that will be edited is %SystemRoot%\System32\drivers\etc
::by default %SystemRoot% is C:\Windows

::Make sure to check services.msc for some other problematic services (like KillerAnalyticsService for users w/ Killer network drivers)

::There is also a proprietary software option for this (OOSU10) that ofc I can't include b/c proprietary.
::Implement DWS (Destroy Windows 10 Spying) if possible. If not, use manually from here (https://github.com/spinda/Destroy-Windows-10-Spying) <- Forked version
:: If I do, include the apache license alongside it (https://www.apache.org/licenses/LICENSE-2.0) as it is licensed under Apache.
:: The original repo for DWS was deleted, and most forks are read only archives now. 
:: Another fork (https://github.com/Wohlstand/Destroy-Windows-10-Spying)

::Another option instead of going through this confusing rigamarole is using Windows 10 Enterprise LTSB. Though I don't know if AutoKMS or W10DigitalActivator work on it.
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

::do these reg changes with reg export file.reg 
::then run that file	
::TODO: Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection set both AllowTelemetry and MaxTelemetryAllowed to 0.
::TODO: check if Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics EnabledExecution can be set to 0.
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
 ::check or query the reg key first before doing add, set can be used if already
 reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WTenBSRemover" /t REG_SZ /d %~0 /f
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
break>%SystemRoot%\System32\drivers\etc\hosts
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

del /s /q "%windir%\tracing\*"
reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Clipboard /v IsClipboardSignalProducingFeatureAvailable /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Clipboard /v IsCloudAndHistoryFeatureAvailable /t REG_DWORD /d 0 /f
::could be catastrophic, will test in detail
:: del %windir%\DiagTrack
:: del %windir%\diagnostics


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
type ms_telemetry_list.txt >> %SystemRoot%\System32\drivers\etc\hosts


::DISM commands. I think of DISM as Disk Image System Management, its a tool that will modify a disk image.
::option "-Online" means I am targeting a currently running disk image, the one you're running the script on.
::This is a proposed solution to the problem of non-removable pre-provisioned packages.
::Log path by default (can be changed by -LogPath) is %WINDIR%\Logs\Dism\dism.log
::found in Windows10Debloater.ps1
::Example:
::powershell -Command Remove-WindowsPackage -Online -NoRestart -PackageName "windows.immersivecontrolpanel_10.0.2.1000_neutral_neutral_cw5n1h2txyewy" -Force


::this could possibly cause a blue screen
del /s /q "C:\Windows\SystemApps\"

::Only if you have another photo viewer
::reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\FilePicker\Config\StartLocation" /v PicturesLibrary /f

powershell -Command "Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online"
powershell -Command "Get-AppxPackage -Name *EventProvider* | Remove-AppxPackage -AllUsers"
powershell -Command "Delete-DeliveryOptimizationCache" -Force
powershell -Command "Disable-AppBackgroundTaskDiagnosticLog"
powershell -Command "Disable-WindowsErrorReporting"
powershell -Command "Get-AppxPackage -Name *Microsoft-WindowsPhone* | Remove-AppxPackage -AllUsers"




REM orig src: https://www.hwinfo.com/misc/RemoveW10Bloat.htm
REM any commented commands are due to an overlap with another command executed elsewhere
REM sc stop DiagTrack
sc stop diagnosticshub.standardcollector.service
REM sc stop dmwappushservice
sc stop WMPNetworkSvc
REM sc stop WSearch

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
move "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy.bak"

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

:: XboxGameCallableUI can no longer be removed this way.
PowerShell -Command "Get-AppxPackage *xbox* | Remove-AppxPackage"

PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
::Commented due to not being able to be removed anymore via this method
:: PowerShell -Command "Get-AppxPackage *ContentDeliveryManager* | Remove-AppxPackage"

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
del %userprofile%\Desktop\OneDriveBackupFiles
pause
start /wait TASKKILL /F /IM explorer.exe
start explorer.exe
REM src end


::Cortana removal mechanism here might cause breaks, comment if problems arise in the forked script
::if not exist RemoveW10Bloat.bat (curl https://raw.githubusercontent.com/InquireWithin/Win.10-SpyWare-Bloat-Telemetry-Remove-Fork/master/RemoveW10Bloat.bat > RemoveW10Bloat.bat)
:: Implement my forked version of w10debloater here
if not exist Windows10Debloater.ps1 (
curl https://raw.githubusercontent.com/InquireWithin/W10BSRemover/main/Windows10Debloater.ps1 > Windows10Debloater.ps1
)

Powershell.exe -Command "& {Start-Process Powershell.exe -ArgumentList '-ExecutionPolicy Bypass -File %~dp0Windows10Debloater.ps1' -Verb RunAs}"

ipconfig /flushdns
exit

