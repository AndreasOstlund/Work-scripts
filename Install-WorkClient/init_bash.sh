#!/bin/sh

/usr/sbin/update-locale LANG=en_US.UTF8

########################################
# package install
# python-dev for pip
# libffi-dev for ansible
# libssl-dev for ansible
apt-get --assume-yes install vim git tmux python-pip python-dev libffi-dev libssl-dev pwgen python-virtualenv
#pip install ansible
#boto is needed by ec2 module
#pip install boto
# github3.py needed by github_release module
#pip install github2 github3.py

#################################
updatedb


###################################
# add local user
useradd --user-group --create-home --groups sudo aos019
USERPWD=$(pwgen -1 -c -n -s 16 1)
echo $USERPWD > /mnt/c/andreas/bash_password.txt
echo "aos019:$USERPWD" | chpasswd



###################################
# set localhost
echo "127.0.0.1 LOVDOT314B" >> /etc/hosts
echo "127.0.0.1 lovdot314b.orebroll.se" >> /etc/hosts

echo "done"
read foo
