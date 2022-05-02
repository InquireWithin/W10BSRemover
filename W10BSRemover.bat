:: 14/4/22 LB

break||(
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
)
:: Most Recent Change: 30/4/22 ("v 1.4")
::If this file was flagged a security risk, know that this is why: https://www.bleepingcomputer.com/news/microsoft/windows-10-hosts-file-blocking-telemetry-is-now-flagged-as-a-risk/
:: justification for not using firewall (at least not yet):
:: Note that Windows will eventually remove the ability to use the batch interpreter to manage its firewall
:: You should also be aware that Microsoft, as the firewall and the OS are propreitary, may have a hidden rule
:: within the code that will interrupt or override these connection blocks.
:: It is much preferred you use almost any other type of firewall or packet blocking/filtering solution
::Some say that microsoft ignores telemetry server blocking via hosts file as well.
::TL;DR use pi hole for blocking microsoft telemetry just to be safe, but the ublock ad list in the preconfig works fine.

::Will probably add OEM-specific debloating and exception handling soon enough

::If this file was flagged a security risk, know that this is why: https://www.bleepingcomputer.com/news/microsoft/windows-10-hosts-file-blocking-telemetry-is-now-flagged-as-a-risk/

::NOTE: This script ASSUMES your registry key:
::HKEY_LOCAL_MACHINES\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath
::is set to
::%SystemRoot%\System32\drivers\etc
::the file that will be edited is %SystemRoot%\System32\drivers\etc
::by default %SystemRoot% is C:\Windows

::Make sure to check services.msc for some other problematic services (like KillerAnalyticsService for users w/ Killer network drivers)
REM Creating a Newline variable (the two blank lines are required!) here in case I use it
set NLM=^
set NL=^^^%NLM%%NLM%^%NLM%%NLM%
::choice /y yn /n /m "heres a choice (y/n)"

::There is also a proprietary software option for this (OOSU10) that ofc I can't include b/c proprietary.
::I need to echo out some warnings to the user or a prompt about lost features here (like onedrive, photos, etc)
::Make a "mini-manual" README file and move this to its own repo
::Implement DWS (Destroy Windows 10 Spying) if possible. If not, use manually from here (https://github.com/spinda/Destroy-Windows-10-Spying) <- Forked version
:: If I do, include the apache license alongside it (https://www.apache.org/licenses/LICENSE-2.0) as it is licensed under Apache.
:: The original repo for DWS was deleted, and most forks are read only archives now. 
:: Another fork (https://github.com/Wohlstand/Destroy-Windows-10-Spying)

@echo off
ver
echo Reminder, This script requires administrator to run.
cd %~dp0
cls
break||(
echo Input options are as follows:
echo.
echo 1 - Use preconfiguration (single file, internet)
echo.
echo 2 - Use preconfiguration (mutli-file, local)
echo.
echo 3 - Quit script
echo. 
echo 4 - Read hosts file
echo.
echo 5 - CLEAN hosts file
echo.
set /P INPUT=
If /I "%INPUT%" == "1" goto one
If /I "%INPUT%" == "2" goto two
If /I "%INPUT%" == "3" goto three
If /I "%INPUT%" == "4" goto four
if /I "%INPUT%" == "5" goto five
EXIT /B 0
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
goto one
:one
::Flush current hosts file and start
break>%SystemRoot%\System32\drivers\etc\hosts
::Two spyware services that have persisted in w10 since inception, deleting them here
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
:bloat. if you're running this script you're not running windows insider, and if you are (for some ungodly reason) remove this line
sc delete wisvc
::the fact that theyve implemented spyware and massive bloat (cortana) into a literal search bar is beyond me.
::Don't worry though, the taskbar looks far better without it, and it can still be accessed via super + s
sc delete WSearch


::open autorun soon and check all the different automatically configured services and remove the spyware-oriented ones




::Servers identified in early w10 builds as telemetry-oriented. I feel that most arent active today, but they stay filtered regardless
if not exist cmd_server_list.bat (curl https://raw.githubusercontent.com/InquireWithin/W10BSRemover/main/cmd_server_list.bat > cmd_server_list.bat)
call cmd_server_list.bat

REM More servers found to be ms telemetry (~467) posted on my github. I originally found these in a reddit comment ages ago. I just formatted them and gave them the prefix "0.0.0.0 "
if not exist ms_telemetry_list.txt (
curl https://github.com/InquireWithin/W10BSRemover/blob/main/ms_telemetry_list.txt >> %SystemRoot%\System32\drivers\etc\hosts
)
else(echo ms_telemetry_list.txt >> %SystemRoot%\System32\drivers\etc\hosts)

::Cortana removal mechanism here might cause breaks, comment if problems arise in the forked script
if not exist RemoveW10Bloat.bat (
curl https://raw.githubusercontent.com/InquireWithin/Win.10-SpyWare-Bloat-Telemetry-Remove-Fork/master/RemoveW10Bloat.bat > RemoveW10Bloat.bat
)
call RemoveW10Bloat.bat
:: Implement my forked version of w10debloater here
if not exist Windows10Debloater.ps1 (
curl https://raw.githubusercontent.com/InquireWithin/W10BSRemover/main/Windows10Debloater.ps1 > Windows10Debloater.ps1
)
powershell Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File 'Windows10Debloater.ps1'" -f $PSCommandPath) -Verb RunAs
ipconfig /flushdns
exit /b 0





::LEGACY INTERFACE (dunno why I even bothered w/ this but if I feel its useful again I'll revamp it to actually have practicality)
::two
::set /A isLocal = 1
::goto one
::exit /b 0

::three
::quit script
::goto:eof
::exit
::exit /b 0

::four
::read from hosts
::for /F "tokens=*" %%A in (%SystemRoot%\System32\drivers\etc\hosts) do (
::  echo %%A
::  )
::goto main
::exit /b 0

::five
::REM you can do this in powershell with Clear-Content as well.
:: This is here as a very primitive "undo" mechanism

::break>%SystemRoot%\System32\drivers\etc\hosts
::goto main
::exit /b 0
