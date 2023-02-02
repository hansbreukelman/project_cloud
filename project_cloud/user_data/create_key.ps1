Start-Process Set-ExecutionPolicy RemoteSigned -Force

aws ssm get-parameter --name /ec2/keypair/key-0ce2de3e9aadbcf63 --with-decryption --query Parameter.Value --output text > KPR_Project_Cloud.pem