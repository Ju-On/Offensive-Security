Setup win2022 server: 192.168.64.138  
Setup Peterparker: \192.168.64.140  
Setup Frankcastle: 192.168.64.139  
Kali: \192.168.64.129/24  

Now that we have compromised an account or have gotten user credentials, further **enumeration** will be conducted with these elevated access.

---

## 🚩 Domain enumeration with ldapdomaindump  

If an IPv6 attack was conducted with mitm6 in combination of ntlmrelayx, there is a possibility a dump was succesfully taken from the lootme -l switch.  

However if not, and the network does not have IPv6 DHCP enabled but we have user credentials from the **initial attack vectors** we can still query the LDAP to fetch us a LDAP domain dump.

    ldapdomaindump ldaps://192.168.64.138 -u 'MARVEL\fcastle' -p Password1

![image](https://github.com/user-attachments/assets/8e4726f9-f194-41f6-b462-0f3a7380eb3b)

---

## 🚩 Domain enumeration with Bloodhound
BloodHound is an AD attack path mapping tool that helps attackers and defenders discovery privilige escalation paths, lateral movement opportunities and AD misconfigurations.  

1. Download and install Bloodhound if it is not already installed.  
2. When first configuring Bloodhound use the below command line. This is also used to start the bloodhound console.  

        sudo neo4j console
![image](https://github.com/user-attachments/assets/79d06ce1-3d4c-4ae2-979b-aefed4fa919b)

4. Click on the link presented in the results to open the console and set a username / password. [neo4j/neo4j1]
5. Once set, open Bloodhound via the command line with 'Bloodhound'
6. Now we need to set an 'ingestor' back in terminal to capture the data. The ingestor will now use the captured creds pointed at the DC.

        root@kali:/home/kali/bloodhound# bloodhound-python -d MARVEL.local -u fcastle -p Password1 -ns 192.168.64.138 -c all

Here i have created a directory specifically for this named bloodhound.  

![image](https://github.com/user-attachments/assets/877d6af9-3c85-4913-882d-31953ca84dc4)

Once the .json files has been captured, we now import it into the Bloodhound console as seen below.  

![image](https://github.com/user-attachments/assets/194f69b9-68d0-4419-a906-d02d693daa7c)

When all data has been loaded, we can now visualise the infomation by using the hamburger drop down.  

![image](https://github.com/user-attachments/assets/e897e37e-c646-4b6e-b31d-8deaa9d909c1)

---

## 🚩 Domain enumeration PlumHound  
PlumHound is a post-processing tool designed for defenders and attackers to analyze BloodHound data efficiently. By simplifing **attack path discovery** and prioritization for AD environments.

1. Firstly download PlumHound from https://github.com/PlumHound/PlumHound.git.
2. Install the downloaded PlumHound package, follow the installation guide in GitHub if required.
3. Install PlumHound in 'venv' if required and run it from the Linux virtualisation.

        cd /opt/PlumHound
        python3 -m venv venv        # Create a virtual environment
        source venv/bin/activate     # Activate the virtual environment
        pip install -r requirements.txt
4. Ensure BloodHound console is still running with the uploaded data, previously collected from the injestor. And run the following command for PlumHound to begin analysing the data.

        (venv) root@kali:/opt/PlumHound# python3 PlumHound.py --easy -p neo4j1

![image](https://github.com/user-attachments/assets/f22f3300-9d94-432c-a8e7-cff4a7027c2d)

5. To run the 'default tasks' run the following query. It is recommended to read through the GitHub page manual for other types of actions it can do.

       (venv) root@kali:/opt/PlumHound# python3 PlumHound.py -x tasks/default.tasks -p neo4j1

![image](https://github.com/user-attachments/assets/193c73bf-8e3b-4076-8bf1-b50ed641a4d2)

From this it has generated further tasks and presented it in the 'Reports.zip' folder for us to analyze.

6. cd into the Reports folder and open **index.html** with firefox for information it has conveniently collected. It has also provided Reports.zip for us to potentially move off and analyze elsewhere.

        kali@kali:/opt/PlumHound/reports$ firefox index.html
note that i am not allowed to execute firefox in root.

![image](https://github.com/user-attachments/assets/e2de3f41-df99-4b2b-87db-4aedafc31051)

---

## 🚩 Domain enumeration with PingCastle
PingCastle is another AD enumeration tool that can be run directly on the target machine as an executable. If for any reason you cannot gain access, it can also be run remotely. It helps assess risks, detect vulnerabilities, and identify misconfigurations in AD environments. Presenting other low hanging fruits such as clear text passwords that may be left out and or te password policy (suggesting if it is weak or not).  

Things it can present within the reports are NTLMv1 configuration, no usage of LAPS (Local Administrator Password Solution).
