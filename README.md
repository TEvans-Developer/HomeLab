# HomeLab
This home lab demonstrates an attack and defense scenario that implements an EDR response using LimaCharlie on a Windows Machine against  Silver (attack ) from a C2 machine (Ubunutu). 

<h3>Disabling Microsoft Defender</h3>
<hr>
<i>What is Microsoft Defender?</i>

<br>Microsft Defender is a comprehensive security tool developed by Microsoft to protect against various types of malware and cyber threats. It includes
real-time protection, firewall and network protection, device performance monitoring and more. 

<i>What do we need to disable Microsoft Defender for this lab?</i>

<br><p style=color:"red"> **Disclaimer. One should not disable Microsoft Defender on their local machine as it is inplaced to help keep your local machine protected from cyber attacks.  For demostaration purposes we will be disabling it on a VM.** </p>

<br> Disabling Microsoft Defender on our Windows Machine is imperative for the attack to be successfull. This will allow for our EDR (LimaCharlie) to detect the attack and respond to it. If Microsoft Defender is enabled the attack will face greater challenges to exploit the Windows Machine.  
