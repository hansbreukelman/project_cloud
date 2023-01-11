from aws_cdk import (
    CfnOutput,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_s3_assets as Asset,
    aws_iam as iam,
    aws_kms as kms,
    Stack,
)

import os

import aws_cdk
from constructs import Construct

# trusted_ip = "86.82.111.120/32"

class ProjectCloudStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)


        #//////////// VPC Webserver \\\\\\\\\\\\

        vpc_webserver = ec2.Vpc(
            self, "VPC_1",
            ip_addresses=ec2.IpAddresses.cidr("10.10.10.0/24"),
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public_web", 
                    cidr_mask=26, 
                    subnet_type=ec2.SubnetType.PUBLIC),
                ]
        )   
        
        web_server_role = iam.Role(
            self, 'webserver-role',
            assumed_by = iam.ServicePrincipal('ec2.amazonaws.com'),
            managed_policies = [iam.ManagedPolicy.from_aws_managed_policy_name('AmazonS3ReadOnlyAccess')],
        )
        
        #//////////// SG Webserver \\\\\\\\\\\\

        SG_webserver = ec2.SecurityGroup(self, "SGwebserver",
            vpc = vpc_webserver,
            security_group_name = "SGWebServer",
            allow_all_outbound = True,
        )

        #HTTP traffic
        SG_webserver.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(80),
        )

        #HTTPS traffic
        SG_webserver.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
        )

        # SSH from the admin server.
        SG_webserver.connections.allow_from(
            ec2.Peer.ipv4("10.20.20.0/24"), 
            ec2.Port.tcp(22)
        )

        #//////////// NACL Webserver \\\\\\\\\\\\

        # NACL webserver
        NACL_webserver = ec2.NetworkAcl(
            self, "NACL_Web", 
            vpc = vpc_webserver,
            subnet_selection = ec2.SubnetSelection(
                subnet_type = ec2.SubnetType.PUBLIC
            )
        )
        # NACL inbound HTTP webserver
        NACL_webserver.add_entry(
            id = "Web HTTP inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 100,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW
        )

        # NACL outbound HTTP webserver
        NACL_webserver.add_entry(
            id = "Web HTTP outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 100,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW
        )

        # NACL inbound HTTPS webserver
        NACL_webserver.add_entry(
            id = "Web HTTPS inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 110,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW
        )

        # NACL outbound HTTPS webserver
        NACL_webserver.add_entry(
            id = "Web HTTPS outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 110,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW
        )

        # NACL inbound Custom TCP webserver
        NACL_webserver.add_entry(
            id = "Web CTCP inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 120,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW
        )

        # NACL outbound Custom TCP webserver
        NACL_webserver.add_entry(
            id = "Web CTCP outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 120,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW
        )
        
        # NACL inbound SSH webserver
        NACL_webserver.add_entry(
            id = "Web SSH inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 125,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW
        )

        #//////////// S3 User Bucket \\\\\\\\\\\\

        Bucket = s3.Bucket(
            self, "userdata_client_test", 
            bucket_name = "bucket-for-userdata", 
            removal_policy = RemovalPolicy.DESTROY,
            encryption = s3.BucketEncryption.S3_MANAGED,
            enforce_ssl = True,
            auto_delete_objects = True
        )
        
        user_data_upload = s3deploy.BucketDeployment(
            self, "DeployWebsite",
            sources = [s3deploy.Source.asset("/Users/hansbreukelman/project_cloud/user_data")],
            destination_bucket = Bucket,
        )

         #//////////// EC2 Instance Webserver \\\\\\\\\\\\

        # --- AMI Webserver ---
        web_ami = ec2.MachineImage.latest_amazon_linux(
            generation = ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            edition = ec2.AmazonLinuxEdition.STANDARD,
            virtualization = ec2.AmazonLinuxVirt.HVM,
            storage = ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
        )
        
        #This is where the user data for the webserver is downloaded.
        userdata_webserver = ec2.UserData.for_linux()
        file_script_path = userdata_webserver.add_s3_download_command(
            bucket = Bucket,
            bucket_key = "user_data.sh",            
        )

        userdata_webserver.add_execute_file_command(file_path = file_script_path) 

        #This is where the index page is downloaded.
        userdata_webserver.add_s3_download_command(
            bucket = Bucket,
            bucket_key = "index.html",
            #local_file = "/tmp/index.html",
            local_file = "/var/www/html/",
        )

        userdata_webserver.add_commands("chmod 755 -R /var/www/html/")

        userdata_webserver.add_execute_file_command(file_path = "/var/www/html/")

        instance_webserver = ec2.Instance(
            self, 'webserver',
            instance_type = ec2.InstanceType('t2.micro'),
            machine_image = web_ami,
            vpc = vpc_webserver,
            security_group = SG_webserver,
            key_name = 'ec2-key-pair', 
            user_data = userdata_webserver,
            role = web_server_role,
            block_devices = [ec2.BlockDevice(
                device_name = "/dev/xvda",
                volume = ec2.BlockDeviceVolume.ebs(
                    volume_size = 8,
                    encrypted = True,
                    delete_on_termination = True,
                ))
            ]
        )

        #//////////// VPC Managementserver \\\\\\\\\\\\

        vpc_managementserver = ec2.Vpc(
            self, "VPC_2",
            ip_addresses=ec2.IpAddresses.cidr("10.20.20.0/24"),
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public_man", 
                    cidr_mask=26, 
                    subnet_type=ec2.SubnetType.PUBLIC),
                ]
        )   
            
        #//////////// SG Managmentserver \\\\\\\\\\\\
            
        SG_managementserver = ec2.SecurityGroup(self, "SGmanagementserver",
            vpc = vpc_managementserver,
            security_group_name = "SGManServer",
            allow_all_outbound = True,
        )
        
        #RDP traffic
        SG_managementserver.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            # ec2.Peer.ipv4(trusted_ip),
            ec2.Port.tcp(3389),
        )
            
        #SSH traffic
        SG_managementserver.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            # ec2.Peer.ipv4(trusted_ip),
            ec2.Port.tcp(22),
        )

        #HTTP traffic
        SG_managementserver.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(80),
        )

        #HTTPS traffic
        SG_managementserver.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
        )
        
        #//////////// NACL Managementserver\\\\\\\\\\\\

        # NACL Managmentserver
        NACL_man = ec2.NetworkAcl(
            self, "NACL_Man", 
            vpc = vpc_managementserver,
            subnet_selection = ec2.SubnetSelection(
                subnet_type = ec2.SubnetType.PUBLIC,
            )
        )
        
        # NACL inbound RDP Managementserver
        NACL_man.add_entry(
            id = "Man RDP inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            # cidr = ec2.AclCidr.ipv4(trusted_ip),
            rule_number = 130,
            traffic = ec2.AclTraffic.tcp_port(3389),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW,
        )
        
        # NACL outbound RDP Managementserver
        NACL_man.add_entry(
            id = "Man RDP outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 130,
            traffic = ec2.AclTraffic.tcp_port(3389),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW,
        )
        
         # NACL inbound SSH Managementserver
        NACL_man.add_entry(
            id = "Man SSH inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            # cidr = ec2.AclCidr.ipv4(trusted_ip),
            rule_number = 140,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW,
        )
        
        # NACL outbound SSH Managementserver
        NACL_man.add_entry(
            id = "Man SSH outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 140,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW,
        ) 
        
        # NACL inbound Custom TCP Managementserver
        NACL_man.add_entry(
            id = "Man CTCP inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 150,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW,
        )

        # NACL outbound Custom TCP Managementserver
        NACL_man.add_entry(
            id = "Man CTCP outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 150,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW,
        )
        
        # NACL inbound HTTP Managementserver
        NACL_man.add_entry(
            id = "Man HTTP inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 160,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW,
        )

        # NACL outbound HTTP Managementserver
        NACL_man.add_entry(
            id = "Man HTTP outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 160,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW,
        )

        # NACL inbound HTTPS Managementserver
        NACL_man.add_entry(
            id = "Man HTTPS inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 170,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW,
        )

        # NACL outbound HTTPS Managementserver
        NACL_man.add_entry(
            id =  "Man HTTPS outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 170,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW,
        )

         #//////////// EC2 Instance Managementserver \\\\\\\\\\\\

        man_ami = ec2.WindowsImage(
            ec2.WindowsVersion.WINDOWS_SERVER_2022_ENGLISH_FULL_BASE,
        )

        # EC2 Admin / Management Server
        instance_managementserver = ec2.Instance(
            self, "adminserver",
            instance_type = ec2.InstanceType('t2.micro'),
            machine_image = man_ami,
            vpc = vpc_managementserver,
            security_group = SG_managementserver,
            key_name = 'ec2-key-pair',
            block_devices = [ec2.BlockDevice(
                device_name = "/dev/sda1",
                volume = ec2.BlockDeviceVolume.ebs(
                    volume_size = 30,
                    encrypted = True,
                    delete_on_termination = True,
                )
            )]
        )

        #VPC peering connection
        VPC_Peering_connection = ec2.CfnVPCPeeringConnection(
            self, "VPCPeeringConnection",
            peer_vpc_id=vpc_managementserver.vpc_id,
            vpc_id=vpc_webserver.vpc_id,
        )

        #Routing table for the adminserver
        for subnet in vpc_managementserver.public_subnets:
            ec2.CfnRoute(
                self, 
                id = f"{subnet.node.id} Managementserver Route Table",
                route_table_id = subnet.route_table.route_table_id,
                destination_cidr_block = "10.10.10.0/24", 
                vpc_peering_connection_id = VPC_Peering_connection.ref,
        )
        
        #Routing table for the webserver
        for subnet in vpc_webserver.public_subnets:
            ec2.CfnRoute(
                self,
                id = f"{subnet.node.id} Webserver Route Table",
                route_table_id = subnet.route_table.route_table_id,
                destination_cidr_block = "10.20.20.0/24", 
                vpc_peering_connection_id = VPC_Peering_connection.ref,
        )
          
        #This is where the user data for the managementserver is described.   
        instance_managementserver.user_data.for_windows()
        instance_managementserver.add_user_data(
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
            "Start-Service sshd",
            "Set-Service -Name sshd -StartupType 'Automatic'",
            "New-NetFirewallRule -Name sshd -DisplayName 'Allow SSH' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22",
        )

        #This is where I set a permission to allow the webserver to read my s3 Bucket.
        Bucket.grant_read(instance_webserver)
        
        #Only direct SSH connections to the admin server is allowed.
        SG_webserver.connections.allow_from(
            other = instance_managementserver,
            port_range = ec2.Port.tcp(22),
        )
