$dlurl = "https://s3.amazonaws.com/aws-cli/AWSCLI64PY3.msi"
$installerPath = Join-Path $env:TEMP (Split-Path $dlurl -Leaf)
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest $dlurl -OutFile $installerPath
Start-Process -FilePath msiexec -Args "/i $installerPath /passive" -Verb RunAs -Wait
Remove-Item $installerPath
$env:Path += ";C:\Program Files\Amazon\AWSCLI\bin"

$dlurl = "https://nodejs.org/dist/v18.13.0/node-v18.13.0-x86.msi"
$installerPath = Join-Path $env:TEMP (Split-Path $dlurl -Leaf)
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest $dlurl -OutFile $installerPath
Start-Process -FilePath msiexec -Args "/i $installerPath /passive" -Verb RunAs -Wait
Remove-Item $installerPath
$env:Path += ";C:\Program Files\Node\npm\bin"

npm install -g aws-cdk

# $keypairid = aws ec2 describe-key-pairs --filters Name=key-name,Values=web_KPR --query KeyPairs[*].KeyPairId --output text

# aws ssm get-parameter --name /ec2/keypair/$keypair --with-decryption --query Parameter.Value --output text > web_KPR.pem