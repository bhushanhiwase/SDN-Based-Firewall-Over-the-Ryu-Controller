# SDN-Based-Firewall-Over-the-Ryu-Controller


Author: Bhushan Hiwase
SJSU ID: 014511445


1. Introduction:
-----------------
This SDN based Firewall runs over the RYU controller and blocks the traffic between the two hosts based on the service such as TCP, UDP, ICMP. The firewall is capable of blocking the service based on the Destination Port number as well. 
The Firewall receives the ACL (Access Control list) from a CSV file. The CSV list is filled by the user only and the user may decide which service should be blocked between two users. The file contains parameters such as source IP, 
Destination IP or the Destination Port number at which the TCP, UDP, or ICMP service should be blocked. The Application then read all these parameters and blocks the traffic between the users mentioned under Source IP and Destination IP. 
 

2. Installation:
-----------------
a. MININET:
   The Mininet is an emulation tool required to create a topology. use the following commands on a Linux-ubuntu machine
to install the mininet application.
	
   	- Steps to install Mininet:
	1) Open the terminal on your Linux Ubuntu18 virtual machine
	2) copy git repo for mininet using this command:'git clone git://github.com/mininet/mininet'
	3) Change directory to the util directory in mininet:'cd mininet/util/'
	4) Finally, run the install.sh file using this command:'bash install.sh'
	5) If the installation is the unsuccessful user may visit 'http://mininet.org/download/' for more download instructions

						OR

	1) On the hypervisor like VirtualBox of Vmware-Workstation import the mininet image
	2) Download the latest Mininet virtual machine image from 'https://github.com/mininet/mininet/wiki/Mininet-VM-Images'.
	3) In Virtualbox :
	   - select File -> Import Appliance and select the .ova you just downloaded. Virtualbox will show
	   you the VM settings and you can then click Import.
	4) Load the Machine and log into the mininet console by entering username and password both as 'mininet'

b. RYU CONTROLLER:
   The Ryu Controller is an SDN based Controller build on python. As the Firewall Application is based on RYU, it is important to install the Ryu controller to run the Firewall Application. 

	- Steps to install RYU Controller:
	1) Open the Ubuntu terminal on your installed ubuntu machine
	2) Run “Sudo apt-get install git python-dev python-setuptools python-pip” to install the packages.
	2) run command 'git clone https://github.com/osrg/ryu.git' to copy the RYU files
	3) Type 'cd ryu'
	4) Type 'sudo pip install' to install the RYU controller.


3. Steps to Run the Firewall Application:
------------------------------------------
After the installation is complete, to run the firewall application and check the blocking states follow the steps below;

a. Fill the ACL entries in Entries.csv file:

	1) Copy the Entries.csv file present in the Project Files folder provided with this README to the installed ryu directory
		you can reach ryu directory using command: 'cd/home/ubuntu/ryu'
	2) After copying the Entries.csv file, change or modify the file with the desired block entries. For example, if the user
	  wants to block ICMP traffic between the source host 10.0.0.1 and the destination host 10.0.0.2 then under the 'SRC_IP' column 
	  enter 10.0.0.1 and under 'DEST_IP' column enter 10.0.0.2 and under 'Blocked service' column write ICMP
	3) If you want to block the traffic destined to the particular port number in TCP or UDP service then write the destination
	  the port number that you want to block under the column 'DEST_IP/Dest_port' column, and write service (TCP or UDP) that you 
	  want to block on that port. 
	4) Make sure that the ACL entries in the Entries.csv file are filled before running the program

b. Load a topology in the mininet:

	1) To test the blocking we create a topology of type linear with 4 nodes and 4 switches. 
	  On the mininet terminal type the following.
	2) SSH to the mininet terminal using Xterm command 'ssh -X mininiet@<IP of mininet machine> xterm'
	3) Load the linear topology on mininer using the following command:
		'sudo mn --topo linear,4  --controller=remote,ip=<IP of the machine having ryu controller>,port=6633
		 --mac --switch=ovsk,protocols=OpenFlow13'


c. Start the Program by copying the 'RYU_SDN_FirewallApplication.py' file into ryu directory, Make sure that the entries in the 
   Entries.csv file has been filled already correctly, as mentioned in step-a. To run the program do following
	1) 'cd ryu' go to the ryu directory where the 'RYU_SDN_FirewallApplication.py' file is present
	2) Run the Firewall application using the following command: 'ryu-manager RYU_SDN_FirewallApplication.py'
		This will start the firewall application, which will block all the traffic inputted in the Entries.csv file.


4. Testing the Firewall:
------------------------
Finally, the user can test if the firewall is running correctly and if the traffic is blocking or not, Following are some helpful commands;

1. ICMP: User may send ICMP traffic between two hosts in mininet using the command:
   use : 'h1 ping h2'

2. Direct TCP: User may use iperf command which finds you the TCP bandwidth between the two users:
   use : ' iperf h1 h2' 

3. UDP and TCP: User may create the UDP traffic by logging into two nodes with the help of xterm and then create a server and make the request:
   - For opening the nodes use: xterm h1 h2

   - To start the TCP server on host while inside the host type: iperf -s -i 1

   - To start TCP server on particular port use: iperf -s -i -p <port number>
					Example: iperf -s -i 1 -p 5008 (here server listens on port 5008)
   
   - To start the UDP server on host while inside the host type: iperf -s -u -i 1
   
   - To start TCP server on particular port use: iperf -s -i -p <port number>
					Example: iperf -s -i 1 -u -p 5010 (here server listens on port 5010)

   - To send the Iperf traffic on the running server use command:
	For TCP : iperf -c <ip of the destination host> -p <Destination port on which server is listining>
		Example : iperf -c 10.0.0.2 -p 5008  (to send traffic to host 10.0.0.2 listening on port 5008) 

	For UDP : iperf -c <ip of the destination host> -u -p <Destination port on which server is listining>
		Example : iperf -c 10.0.0.2 -u -p 5010 (to send traffic to host 10.0.0.2 listening on port 5010) 


Using the above commands the user can test the complete topology and test the working of the firewall.
