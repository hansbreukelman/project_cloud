#!/bin/bash

sudo yum update -y
sudo yum install -y httpd
# sudo service httpd start
# sudo service httpd enable
sudo systemctl enable httpd
sudo systemctl start httpd