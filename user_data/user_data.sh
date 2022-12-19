#!/bin/bash

sudo yum update
sudo yum -y install httpd
sudo systemctl enable httpd
sudo systemctl start httpd