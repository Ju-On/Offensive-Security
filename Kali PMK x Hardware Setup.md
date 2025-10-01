# Guide To Enable Cross Compatability VMWARE Workstation To Hardware

To reinstate back to original state read below, GPT prompt is also provided.

## Steps:  
download wmware work station  
download kali iso  
run apt update && install  
install pmk by dewault  
install VMware workstation tools  

## Enable Hardware Cross Compatability
config VMware to virtual intel x v-intel settings  
    
    # removed regkeys for virtualisation (deleted) and certain flags set off  
    # turned off core isolation  
    # flicked off virtualisation in local group policy  
    # win+r > optional features > windows features > windows hypervisor platform turned off  

-----
    
## To Reinstate Original Memory Isolation and Hyper-V on Win11
Checklist to Return to Normal State (Windows 11 Default)
1. Re-enable Hyper-V features

Open Windows Features (optionalfeatures)

Tick the boxes for:

* Hyper-V (and its sub-features)

* Virtual Machine Platform

* Windows Hypervisor Platform

Click OK → Restart.

2. Re-enable Virtualization-Based Security (VBS)

Open Local Group Policy Editor (gpedit.msc)

Navigate: Computer Configuration → Administrative Templates → System → Device Guard

Set Turn on Virtualization Based Security → Enabled

Run Powershell:

    gpupdate /force

3. Re-enable Core Isolation / Memory Integrity

* Go to Windows Security → Device Security → Core isolation details

* Toggle Memory Integrity → On

* Restart.

4. Reset boot options

Run in PowerShell (Admin):

    bcdedit /set "{current}" hypervisorlaunchtype auto
    bcdedit /set "{current}" vsmlaunchtype auto

5. Recreate registry values (optional, if not auto-restored)

Run in PowerShell (Admin):

    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f

6. Confirm it worked

Run Powershell:

    systeminfo | findstr /i "Virtualization"


You should see:

* “Virtualisation-based security: Running”

* “A hypervisor has been detected”

And in msinfo32 → “Virtualisation-based security: Running”.

## ChatGPT prompt for guide

When you’re ready to revert, just tell me:

* “I want to return to my original Windows security state (Hyper-V, VBS, Credential Guard back on).”

Show me the output of:

    systeminfo | findstr /i "Virtualization"
    bcdedit /enum "{current}" | findstr hypervisorlaunchtype
    msinfo32
