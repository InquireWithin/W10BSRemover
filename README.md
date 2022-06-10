# W10BSRemover

[![made-with-powershell](https://img.shields.io/badge/PowerShell-1f425f?logo=Powershell)](https://microsoft.com/PowerShell)
[![made-with-batch](https://img.shields.io/badge/Windows-Batch-lightgrey)](https://ss64.com/nt/)
[![License: GPL3](https://img.shields.io/badge/license-GPL-blue)](https://www.gnu.org/licenses/gpl-3.0.en.html)

A BAT/PS1 script designed to help quell and quench some of Windows 10's bloatware and spyware (BS), and telemetry both locally (services, regkeys, schtasks, PUPs) and remotely (hosts file edit).


The ONLY REQUIRED FILE is W10BSRemover.bat OR W10CustomBSRemover.ps1 (if you have internet connection on the target machine). Otherwise, download (preferably clone) the repo w/ all the files in the same directory and same original names, then run W10Remover.bat or W10CustomBSRemover.ps1.


If you use the ps1 file, be sure to customize it to your liking by editing the global variables found near the top of the script, as either 0 or 1 depending. This is a placeholder to allow customization if I ever make a GUI.


Copyright of https://github.com/InquireWithin 2022


**This script is _NOT_ tested for W11 yet**, though Microsoft usually will keep a lot of these legacy reg keys and such. I've heard claims that the DRM has increased by a very noticable magnitude. Partial functionality is likely; expect non-fatal errors to pop up if running on W11.

## Reminder for AV users
##### (Specifically Microsoft Defender or W10 Default AV)
This script, and others similar, may be flagged as malware due to the editing of the hosts file in order to cancel out microsoft remote server pings and windows keylogger file uploads. It will claim 'HostsFileHijack' due to **the specfic servers being blocked**, as Microsoft deems these "essential" to OS functionality. This is untrue if you've ever done anything ever on an offline machine. Most of these servers have no practical usage, nor should operating systems be reliant on remote servers for functionality.

## Disclaimer
No, I am not responsible for anything to your system, nor am I responsible for any changes in any form to your system. I highly advise you use one of the STABLE versions in the repo or commit history. If there isn't any suffix on the latest version, it's implied to be stable. There is no warranty for this software (see LICENSE). You are running this hopefully with the knowledge of what the script does and you are running this at your own discretion. By running the script, you acknowledge this risk. I suggest you get a barebones understanding of what is happening so you can course correct should any unwanted behavior occur (likely due to windows trying to correct these changes). This isn't mandatory and the script will work swimmingly regardless, but it's always a good idea to check the code.

This script was never, explicitly or implicity, claiming to remove ALL Windows bloat, spyware, or telemetry (See {6}). The goal is to pluck apart and silence the most apparent, low-hanging bloat, alongside some more hidden junk without going into "breaking the OS" territory. The intent is to utilize my anecdotal experience alongside other user's findings to remove __as much as feasible__. "Bloat" is subjective, and you should comment/remove lines of code that remove something you may consider useful. I may curate this in the future. Also, fully debloating a proprietary operating system is essentially an impossible ask. If you're this worried, use Linux (I recommend Mint, Arco, Void, or Garuda if you wish to keep something that "just works"). 

Yes, there are a couple bugs (see {4} and changelog.txt), that's the name of the software game. I try to resolve what I can.
Yes, it is relatively unpolished. At the end of the day, it's a script originally designed for personal use: I made it public for others' benefit.

## Impacts of this script on your system
##### NOTE: Nearly all of these can be reverted with code edits
IF you feel that you need some of the "bloat" (default microsoft apps, ms office, ms accounts from browser, etc), download or clone all the files in this repo, and remove the lines of Batch/PowerShell (in Windows10Debloater.ps1 and/or the W10BSRemover.bat) that mention those specific packages or utilities.
Restart system after execution for some changes to take effect: These changes will be made on next system startup regardless

This script was designed with the intent of being ran PRIOR to user account creation or much personalization or usage of the OS (except in the case of {5}). You can run this whenever though I advise executing it after a fresh OS install.

## Reversing
Since I assume you know what you're doing to a reasonable extent if you run this, I haven't made a proper reversal script yet. This is also because nearly all unintended effects can be alleviated with the following:

`sfc /scannow

DISM.exe /Online /Cleanup-image /Scanhealth

DISM.exe /Online /Cleanup-image /Restorehealth`

Also, once again, use the W10CustomBSRemover.ps1 and edit the variables if you feel as though you may need some default windows services, apps, etc. The batch version of this script is intended to be the harshest to windows defaults.

**Most of the following apply if you run the batch variant of this script, which you shouldn't unless you're familiar with what the script does.**

**{1} Microsoft Domains**

Firstly, you will be **UNABLE** to access nearly all domains with *'microsoft'* in them (except most notably docs.microsoft.com), and a good chunk of Microsoft Office (see {2}). You will also be hard-pressed upon attempting to sign in to Microsoft accounts except the user account (see {3}). This can be resolved quickly by either commenting/removing the line to `curl` the *ms_telemetry_list.txt* or you can do:

`break>%SystemRoot%\System32\drivers\etc\hosts` 

which will allow connection to microsoft domains again but also remove all the other telemetry servers, see {3} for other options.

**{2} Microsoft Office**

Many users rely on the Microsoft office suite of tools (Word, Excel, PowerPoint, etc). While these are very handy and have helped me plenty over the years, I feel the need to also pull the plug on them (in the batch script). I suggest you use 
LibreOffice (https://www.libreoffice.org/) instead: This set of software nearly mirrors the functionality of Microsoft Office and makes the transition seamless. It can read and write to all Microsoft Office file extensions (docx, xlsx, ppt, etc) so there is zero downside or loss of functionality. 

**{3} Microsoft Accounts (excluding system/user account)**

Microsoft account sign-ins will be quite daunting after running the batch script as is. To allow for this, set "UseLightHostsFile = 1" in the ps1 script before running. I'm fully aware that many people require this, so I once again will present three potential solutions to this in cmd (if you already ran the .bat version instead):

<1>

Fixes in all cases

`break>%SystemRoot%\System32\Drivers\etc\hosts && ipconfig /flushdns`

<2> 

This assumes you have already ran the script. Make sure it's on one line

`findstr /v /c:"microsoft" /c:"office" /c:"live" %SystemRoot%\System32\drivers\etc\hosts > %SystemRoot%\System32\drivers\etc\hosts`

<3>

This assumes you have NOT ran the script and downloaded everything locally, replace Path\To\File with the location of ms_telemetry_list.txt. Keep this to one line.

`findstr /v /c:"microsoft" /c:"office" /c:"live" Path\To\File\ms_telemetry_list.txt > Path\To\File\ms_telemetry_list.txt`

<4>

If you have NOT ran W10BSRemover.bat yet and are relying on internet connection for ms_telemetry_list.txt, run the script anyway and then do <2>

**{4} Gaming**

I still have a Windows 10 boot specifically because I like playing games in some of my off time and Proton/Wine can't support everything. I MUST preface by saying that, *anytime you launch a game* (especially from Steam as W10 *knows* it's a game), you will be prompted with: "you need an app to open ms-gamingoverlay link" or something related. Do not panic, this is countered by alt tabbing or clicking off of it. The reason this occurs is due to Microsoft's analytics wanting to know if you're gaming, which game you're playing, and for how long. This is obviously not essential to operating system functionality. Yes, its annoying to deal w/ it every time a game is launched, but it's worth it as a simple click or key combo ripostes this nuisance. More and more games seem to be getting Linux support and Windows 11 caps your frames with its glaringly obvious hardware restraints and stress. This is not a hardware issue, this is an operating system issue, and I tried to reduce the ridiculous amount of read writes and mem usage Windows eats up.

**{5} Microsoft Store**

I don't truly know how many people actually utilize the Microsoft Store; what I *do* know is that it's a source of bloat in most cases. It is useless except in the event that an application is ONLY avaliable through the MS Store and not in a readily accessible binary via their site, or anywhere else. You may need it for some ungodly DRM-packed software (like HP Smart). This script by and large nukes Microsoft Store into the dirt, so download what proprietary nonsense you need prior to running the script. If you haven't and already ran the script, you can try to piece it together with a couple of restarts and do {3}<1>, or better yet, do the commands listed in the "Reversal" subsection, or the system backup if you ran the ps1 script with the corresponding variable set to 1.


If you haven't for whatever reason gone into developer settings and enabled "Allow third party ..." to invalidate 95% of the MS Store's use case, do so, as I haven't included it in the script.

**{6} LIMITATIONS**

There are many limitations on applying such a script in the current year, and there's a good reason you dont hear of any continued development on this topic, as it gets mostly invalidated by what I'm about to tell you.


I am convinced it is an impossibility to scrub away and remove provisioned packages from a running ISO. Such a thing used to be quite simple a few years back, you'd just do a Remove-AppxPackage or Remove-AppxProvisionedPackage (seemingly useless half of the time now). The difference between a provisioned package and one that is installed is that the provisioned packages are built into the ISO itself, and are immediately deployed upon the creation of a new user account (which is why you should clean the disk image before a new user account is first created). Removal for this seems to be patched up all the time (Also why I recommend using an older ISO archived somewhere).


It's not just provisioned packages, most system folders and their subdirectories, alongside specific reg keys and services, are protected by SYSTEM. This may be worked out at a later date via implementation of an NTAuthority account w/ C# calls. Another choice would be using icacls or similar to deny SYSTEM access to certain folders containing undesired binaries and denying access to configurations (usually XML files) for packages w/o a binary.


and more utter nonsense that I'm too infuriated by to list here.


Ending tasks with SYSTEM level is also an impossibility so the best bet is the registry, however some of those keys revert back at pseudorandom times. Services will sometimes start regardless if they've been completely disabled. Systemapp "removal" method is dodgy and likely to be patched soon or was patched in W11.


Everything in this OS is an inconsistent array of half-baked systems piled atop eachother and set ablaze while Microsoft dances around it.  Archive any old ISO's you have and never use W10 for anything except RevEng or Gaming (the latter if you absolutely must, though I recommend using QEMU/VirtManager rather than bare metal). 


The most agonizing thought of all this is that Windows 11 has magnified all the horrors of the aforementioned, and that was the only purpose for its creation.


**{7} Concluding Statement and Known Bugs/Inconsistencies**

Lastly, this script is a bit "volatile". What I mean by this is that **effects on individual systems may vary**. I am not responsible for any system damage, data loss, or unwanted behavior. However, I should state that these variations are very mild. To name a few I have seen: 

1) Search bar retaining functionality on some systems, while being entirely inacessible for others (Seems patched). Use the search bar via windows + s.

2) VirtualBox VM's refusing to run commands within the script despite elevation

3) Occasionally the OS takes a couple extra seconds to log in the user account, or shut down. (I assume this is it trying to course correct itself, so its unfixable)

4) Microsoft office software being unusuable (intended in most cases, see {2}), while on others no effect occurs (or Microsoft undoes the changes)

5) Breakage of `curl` due to MS edge suppression (seems resolved)

6) QEMU VM runs the script and stagnates (fix with "CTRL + C" to exit script, open cmd and use `taskkill.exe /f /im explorer.exe && start explorer.exe`)

7) system time inaccuracy (break hosts file, sync time in settings, rerun to fix. Will occur regardless if you use the script or not upon booting into windows if you have a second boot)

8) Certain Microsoft Services starting up or booting again as a response to their "first line of defense" being neutered.

9) This is the most impactful bug ive seen thus far: Taskbar taking roughly a couple minutes after boot to load up. This only ever happened in a single instance and hasn't been found since. I don't know the source of the issue or whether it is still possible.
