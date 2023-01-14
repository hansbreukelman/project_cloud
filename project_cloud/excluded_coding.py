        
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