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

Start-Process aws configure
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait('AKIA5SF23W4ZYKGQNUN4{ENTER}')
Start-Sleep 1
[System.Windows.Forms.SendKeys]::SendWait('QV8qqCo3Kd/QQebMb/g1IIdJUU7DLVcszzbWJ1sH{ENTER}')
Start-Sleep 1
[System.Windows.Forms.SendKeys]::SendWait('eu-central-1{ENTER}')
Start-Sleep 1
[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
Start-Sleep 1
[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')

Start-Process $keypairid = Start-Process aws ec2 describe-key-pairs --filters Name=key-name,Values=project_cloud_KPR --query KeyPairs[*].KeyPairId --output text

Start-Process aws ssm get-parameter --name /ec2/keypair/$keypair --with-decryption --query Parameter.Value --output text > project_cloud_KPR.pem
