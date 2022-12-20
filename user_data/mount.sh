#!/bin/bash

# check if disk is already partitioned
sudo parted -s /dev/nvme1n1 print 1  &> /dev/null

# if status code == 1, then partition not found 
# partition disk, add to fstab and mount all
if [ $? -eq 1 ]; then
    sudo mkfs -t xfs /dev/nvme1n1
    sudo mkdir -p /data
    sleep 3

    #get UUID of device
    UUID=$(lsblk -f | grep 'nvme1n1' | awk '{ print $3 }')

    # make backup of fstab
    sudo cp /etc/fstab /etc/fstab.orig

    # add device to fstab
    echo "UUID=${UUID}  /data  xfs  defaults,nofail  0  2" | sudo tee -a /etc/fstab

fi

sudo mount -a