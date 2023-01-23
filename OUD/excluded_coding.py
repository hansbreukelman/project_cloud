        
                # web_server_role = iam.Role(
        #     self, 'webserver-role',
        #     assumed_by = iam.ServicePrincipal('ec2.amazonaws.com'),
        #     managed_policies = [iam.ManagedPolicy.from_aws_managed_policy_name('AmazonS3ReadOnlyAccess')],
        # )
        
        
        #This is where the user data for the managementserver is described.   
        # instance_managementserver.user_data.for_windows()
        # instance_managementserver.add_user_data(
        #     "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
        #     "Start-Service sshd",
        #     "Set-Service -Name sshd -StartupType 'Automatic'",
        #     "New-NetFirewallRule -Name sshd -DisplayName 'Allow SSH' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22",
        # )
        
        # role = web_server_role,
        
        # self.backup_vault.apply_removal_policy(RemovalPolicy.DESTROY)
        # self.backup_plan.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # ud_source = assets.Asset(self, "ud_source", path= r"./project_atalla/user_data.sh")
        # ud_policy = ud_source.bucket.grant_read(web_server.role)
        # ud_path = web_server.user_data.add_s3_download_command(bucket = ud_source.bucket, bucket_key = ud_source.s3_object_key)
        # ud_exe = web_server.user_data.add_execute_file_command(file_path = ud_path)

        # self.webserver = web_server
        
        # userdata_manserver = ec2.CloudFormationInit.from_elements(
        #         ec2.InitCommand.argv_command([
        #         'powershell.exe',
        #         '-command',
        #         'Set-ExecutionPolicy RemoteSigned -Force'
        #         ]),
        #     )
        
         # instance_managementserver.user_data.for_windows()
        # instance_managementserver.add_user_data(
        #     "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
        #     "Start-Service sshd",
        #     "Set-Service -Name sshd -StartupType 'Automatic'",
        #     "New-NetFirewallRule -Name sshd -DisplayName 'Allow SSH' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22",
        # )
        
        # instance_managementserver = ec2.InitCommand.argvCommand([
        #     'powershell.exe',
        #     '-command',
        #     'Set-ExecutionPolicy RemoteSigned -Force'
        #     ])
        
# $dlurl = "https://nodejs.org/dist/v18.13.0/node-v18.13.0-x86.msi"
# $installerPath = Join-Path $env:TEMP (Split-Path $dlurl -Leaf)
# $ProgressPreference = 'SilentlyContinue'
# Invoke-WebRequest $dlurl -OutFile $installerPath
# Start-Process -FilePath msiexec -Args "/i $installerPath /passive" -Verb RunAs -Wait
# Remove-Item $installerPath
# $env:Path += ";C:\Program Files\Node\npm\bin"

# #HTTP traffic
#         SG_managementserver.add_ingress_rule(
#             ec2.Peer.any_ipv4(),
#             ec2.Port.tcp(80),
#         )

#         #HTTPS traffic
#         SG_managementserver.add_ingress_rule(
#             ec2.Peer.any_ipv4(),
#             ec2.Port.tcp(443),
#         )

        # #Create a rule that allow SSH from the admin server.
        # SG_webserver.connections.allow_from(
        #     ec2.Peer.ipv4("10.20.20.0/24"), ec2.Port.tcp(22))
        
        #  EC2InstanceRole = iam.Role(self, "Role",
        #     assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
        #     managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")],
        #     description="This is a custom role for assuming SSM role"
        # )
        
        # role=EC2InstanceRole,