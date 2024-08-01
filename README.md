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

<h3>Disable Microsft Machine</h3>
I. On your Windows Machine Click "Start" menu icon.
<br>II. Click "Settings"
<br>III. Click "Privacy and Security" 
<br>IV. Click "Windows Security"
<br>V. Click "Virus & Threat protection"
<br>VI. Underneath the "Virus & Threat protection settings" click "Manage Settings"
<br>VII. Toggle OFF the "Tamper protection" switch. When promtped click yes to allow the changes.

<br>![Screenshot (78)](https://github.com/user-attachments/assets/11c5d2c9-829f-4c22-8c43-2b2a225d0f04)

<br>VIII. Continue to toggle OFF ever other option here, then close the window we opened.

