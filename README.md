# README: SSH Bruteforce SDS Project

## Introduction

Welcome to the SSH Bruteforce SDS (Software Defined Security) project! This project aims to demonstrate the vulnerabilities associated with weak SSH (Secure Shell) credentials in network security.

## Requirements

- Python 3.x
- Mininet

## Installation

1. Clone the SSH Bruteforce SDS project repository:
    ```
    git clone https://github.com/maxbekh/sshbruteforce_sds.git
    ```

2. Clone and install Mininet:
    ```
    git clone https://github.com/mininet/mininet
    cd mininet
    git checkout -b mininet-2.3.1b4
    util/install.sh -a
    ```

## Usage

1. Navigate to the SSH Bruteforce SDS project directory.
    ```
    cd sshbruteforce_sds
    ```

2. Launch the network topology setup script with superuser privileges:
    ```
    sudo python3 topo.py
    ```

## Additional Notes

- Ensure that Python 3.x is installed on your system.
- Mininet is required to emulate the network environment. Make sure to clone the Mininet repository as instructed in the installation steps.
- Running the `topo.py` script sets up the network topology for the SSH bruteforce demonstration.

## Disclaimer

This project is for educational purposes only. It aims to raise awareness about the importance of strong SSH credentials and the risks associated with weak passwords. Unauthorized access to computer systems is illegal and unethical. Always use this project responsibly and with the appropriate permissions.

## Contributors

## License

