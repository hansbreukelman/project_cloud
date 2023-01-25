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