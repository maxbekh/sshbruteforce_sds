# README: SSH Bruteforce SDS Project

## Introduction

Welcome to the SSH Bruteforce SDS (Software Defined Security) project! This project aims to demonstrate the vulnerabilities associated with weak SSH (Secure Shell) credentials in network security for the SDS course at UPC.

## Requirements

- GNS3 
- Python3

## Installation

1. Clone the SSH Bruteforce SDS project repository:
    ```
    git clone https://github.com/maxbekh/sshbruteforce_sds.git
    ```
2. Clone the GNS3 project repository: 
    ```
    git clone https://github.com/GNS3/gns3-server.git
    ```
3. Install the GNS3 server:
    ```
    cd gns3-server
    sudo apt-get install python3-setuptools python3-pip
    python3 -m pip install -r requirements.txt
    python3 -m pip install .
    gns3server
    ```
4. Import the [GNS3 project file](gns3/sds_project.gns3project):
    ```
    Open GNS3
    File -> Import Portable Project -> sds_project.gns3project
    ```

## Configuration
I dont't know if gns3 project config file keep configuration of network interfaces but they are discussed in the final report.
This includes the following:
- Network interfaces for hosts
- R1 config that is here: [R1 config](routers/cisco_r1_startup.cfg)
- OpenVSwtich config:
````
sudo ovs-vsctl set bridge br0 protocols=OpenFlow13
sudo ovs-vsctl set-controller br0 tcp:10.0.0.20:6633
````

## Start
After GNS3 is up and running, start the following components in the following order to get normal communication (should work without order but it is better to start in this order):
1. Start the R1
2. Start the Ryu controller
3. Start the OpenVSwitch
4. Start other hosts


## Attacker
Attacker use python and so need to use virtual environment to use the required libraries. 
```
cd sshbruteforce_sds/arp
source venv/bin/activate
python3 arp_attack.py
```

## Ryu
To run the Ryu controller, use the following command:
```
cd sshbruteforce_sds/ryu
ryu-manager arp_firewall.py
or
ryu-manager ssh_bruteforce_firewall.py
```

## Docker container

All dockerfiles are located [here](docker/). Images are available on Docker Hub at maxbekh/sshbruteforce_sds-X, where X is the name of the image (attacker, server, client or ryu). 
To build the image, run the following command:
```
docker buildx build --push --platform linux/amd64 -t {YourName}/sshbruteforce_sds-X -f Dockerfile.X .
```

## Disclaimer

This project is for educational purposes only. It aims to raise awareness about the importance of strong SSH credentials and the risks associated with weak passwords. Unauthorized access to computer systems is illegal and unethical. Always use this project responsibly and with the appropriate permissions.
