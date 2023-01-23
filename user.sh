#!/bin/bash

keypairs=$((aws ec2 describe-key-pairs --filters Name=key-name,Values=web_KPR --query KeyPairs[*].KeyPairId --output text))

aws ssm get-parameter --name /ec2/keypair/$keypairs --with-decryption --query Parameter.Value --output text > web_KPR.pem

# outcome="/ec2/keypair/$keypair"

# aws ssm get-parameter --name  --with-decryption --query Parameter.Value --output text > web_KPR.pem