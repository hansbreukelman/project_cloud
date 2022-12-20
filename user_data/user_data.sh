#!/bin/bash

sudo yum update
sudo yum -y install httpd
sudo systemctl enable httpd
sudo systemctl start httpd
sudo mkdir -p $(dirname '/var/www/html/user_data.sh')
sudo chmod 755 -R /var/www/html/user_data.sh