$keypairid = Start-Process aws ec2 describe-key-pairs --filters Name=key-name,Values=project_cloud_KPR --query KeyPairs[*].KeyPairId --output text

Start-Process aws ssm get-parameter --name /ec2/keypair/$keypair --with-decryption --query Parameter.Value --output text > project_cloud_KPR.pem

