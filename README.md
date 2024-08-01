# HomeLab
This home lab demonstrates an attack and defense scenario that implements an EDR response using LimaCharlie on a Windows Machine against  Silver (attack ) from a C2 machine (Ubunutu). 

<h2>Disabling Microsoft Defender</h3>
<hr>
<i>What is Microsoft Defender?</i>

<br>Microsft Defender is a comprehensive security tool developed by Microsoft to protect against various types of malware and cyber threats. It includes
real-time protection, firewall and network protection, device performance monitoring and more. 

<i>What do we need to disable Microsoft Defender for this lab?</i>

<br><b> **Disclaimer. One should not disable Microsoft Defender on their local machine as it is inplaced to help keep your local machine protected from cyber attacks.  For demostaration purposes we will be disabling it on a VM.** </b>

<br> Disabling Microsoft Defender on our Windows Machine is imperative for the attack to be successfull. This will allow for our EDR (LimaCharlie) to detect the attack and respond to it. If Microsoft Defender and its features are enabled the attack will face greater challenges to exploit the Windows Machine. Again, for demostration purposes we will disable Microsoft Windows on a virtual machine to demostrate the attack and defense.   

<h3> Steps</h3>
Set up the Windows Machine, then sign into the machine.

<br>*** LINK HERE***

<h3> A. Disabling Tamper Protection</h3>
i. On your Windows Machine Click "Start" menu icon.
<br>ii. Click "Settings"
<br>iii. Click "Privacy and Security" 
<br>iv. Click "Windows Security"
<br>v. Click "Virus & Threat protection"
<br>vi. Underneath the "Virus & Threat protection settings" click "Manage Settings"
<br>vii. Toggle OFF the "Tamper protection" switch. When promtped click yes to allow the changes.

<br>![Screenshot (78)](https://github.com/user-attachments/assets/11c5d2c9-829f-4c22-8c43-2b2a225d0f04)

<br>VIII. Continue to toggle OFF ever other option here, then close the window we opened.

<h3>B. Disable Defender via Group Policy Editor</h3>
i. Click on "Start" menu icon.
<br>ii. In the search bar type "cmd" and right click to "Run as administrator" then run the command "gpedit.msc"
<br>iii. Once prompted , click Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus
<br>iv. Double-click "Turn off Microsoft Defender Antivirius", then select "Enabled" > Click "Apply" > Click "OK"

<br>![Screenshot (79)](https://github.com/user-attachments/assets/ab0d1ab4-e480-46ef-8e26-5e8cdacd79be)

<br> <i>** Enabling the policy will make it so that Microsoft Defenders Antivirius does not run and will not scan for malware and other unneeded software.  </i>

<h3>C. Perm. disable Defender via Registry </h3>
i. From the same command terminal , enter the command.

<br><i> REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f </i>

<h3> Prepare to boot into "Safe Mode" to disable all Defender services</h3>
i. Click "Start" menu icon
<br>ii. Type "msconfig" into the search bar within the Start Menu
<br>iii. Navigate to the "Boot" tab and select "Boot Options", from there you wil click the "Safe Boot" box leaving the "Minimal" button enabled. 
<br>iv. Click "Apply" > "OK". 

<br>![Screenshot (80)](https://github.com/user-attachments/assets/cda91548-4fa0-43bc-877b-7caaa7b42b81)



<br>v.Allow the System to "Restart" in Safe Mode and re-sign in. Once signed in you will notice the save mode at the top of the left corner of the Machine. 

<h3>Disabling services via the Registry while in Safe Mode</h3>
i. Click the "Start" menu icon
<br>ii. Search for "regedit" in the search menu. 
<br>iii. For each registry location you will need to browse to the key, "Start" value and change each one to 4. The registrys path you will need to follow is >  Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services

<br> each will end in >  \Sense; \WdBoot; \ WindDefend; \WdNisDrv; \WdNisSvc; \WdFilter

<br>![Screenshot (81)](https://github.com/user-attachments/assets/9f687111-895b-4b32-8b9e-ff6224ec7788)



