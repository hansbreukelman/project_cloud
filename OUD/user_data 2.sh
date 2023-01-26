#!/bin/bash

sudo yum update -y
sudo yum install httpd -y
sudo systemctl start httpd
sudo systemctl enable httpd

sudo echo "Welcome to Wim's AWS Project!" > /var/www/html/index.html