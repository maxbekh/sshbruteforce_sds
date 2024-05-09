# Base image for client
FROM ubuntu:latest as client_base

# Install SSH client
RUN apt-get update && \
    apt-get install -y openssh-client

# Create an SSH user
ARG USERNAME=user
ARG PASSWORD=password

# Assign a unique UID for the first client user
ARG USER1_UID=1001
RUN useradd -rm -d /home/$USERNAME -s /bin/bash -g root -G sudo -u $USER1_UID $USERNAME && \
    echo "$USERNAME:$PASSWORD" | chpasswd && \
    mkdir /var/run/sshd

# Expose the SSH port
EXPOSE 22

# Start SSH client on container startup (only for client)
CMD ["sleep", "infinity"]

# Install SSH server (for server)
FROM ubuntu:latest as server_base

# Install SSH server
# Update packages and install openssh-server
RUN apt-get update && \
    apt-get install -y openssh-server && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    service ssh restart


# Create an SSH user
ARG USERNAME=user
ARG PASSWORD=password

# Assign a unique UID for the second client user
ARG USER2_UID=1002
RUN useradd -rm -d /home/$USERNAME -s /bin/bash -g root -G sudo -u $USER2_UID $USERNAME && \
    echo "$USERNAME:$PASSWORD" | chpasswd && \
    mkdir /var/run/sshd

# Expose the SSH port
EXPOSE 22

# Start SSH server on container startup (only for server)
CMD ["/usr/sbin/sshd", "-D"]
