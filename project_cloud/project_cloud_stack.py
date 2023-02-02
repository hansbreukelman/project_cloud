from aws_cdk import (
    RemovalPolicy,
    Duration,
    Stack,
    aws_ec2 as ec2,
    aws_s3 as s3,
    RemovalPolicy,
    aws_s3_deployment as s3deploy,
    aws_iam as iam,
    aws_backup as backup,
    aws_events as events,
    aws_elasticloadbalancingv2 as elb,
    aws_autoscaling as autoscaling,
    aws_autoscaling as autoscale,
    aws_certificatemanager as acm,
    aws_ram as ram,
    aws_kms as kms,
)

from constructs import Construct

from requests import get

trusted_ip = get('https://api.ipify.org').text + '/32'

class ProjectCloudStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs) 
        
        ################################################
         #////////////// VPC Webserver \\\\\\\\\\\\\\\\\
        ################################################
        
        vpc_webserver = ec2.Vpc(self, "VPC_1",
            ip_addresses=ec2.IpAddresses.cidr("10.10.10.0/24"),
            vpc_name = "vpc_webserver",
            nat_gateways = 1,
            max_azs=3,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name = "public_web",
                    cidr_mask = 26,
                    subnet_type = ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(
                    name = "private_web", 
                    cidr_mask = 28, 
                    subnet_type = ec2.SubnetType.PRIVATE_WITH_EGRESS),]) 
        
        # >>>>>>>>> SecurityGroup Webserver <<<<<<<<<<
        SG_webserver = ec2.SecurityGroup(self, "SGwebserver",
            vpc = vpc_webserver,
            description = "SGWebServer",
            allow_all_outbound = True,)
        
        # NACL webserver private
        NACL_Ws_Private = ec2.NetworkAcl(
            self, "NACL_Web_Private", 
            vpc = vpc_webserver,
            subnet_selection = ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS))
        
        # NACL webserver public
        NACL_Ws_Public = ec2.NetworkAcl(
            self, "NACL_Web_Public", 
            vpc = vpc_webserver,
            subnet_selection = ec2.SubnetSelection(
                subnet_type = ec2.SubnetType.PUBLIC))

        
        ################################################
        #//////////// VPC Managementserver \\\\\\\\\\\\
        ################################################
        
        vpc_managementserver = ec2.Vpc( self, "VPC_2",
            ip_addresses=ec2.IpAddresses.cidr("10.20.20.0/24"),
            vpc_name = "vpc_managementserver",
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public_man", 
                    cidr_mask=25, 
                    subnet_type=ec2.SubnetType.PUBLIC),])
        
        # >>>>>>> SecurityGroup Managmentserver <<<<<<<<
        SG_managementserver = ec2.SecurityGroup(self, "SGmanagementserver",
            vpc = vpc_managementserver,
            description = "SGManServer",
            allow_all_outbound = True,)
        
        # NACL Managmentserver
        NACL_man = ec2.NetworkAcl(
            self, "NACL_Man", 
            vpc = vpc_managementserver,
            subnet_selection = ec2.SubnetSelection(
                subnet_type = ec2.SubnetType.PUBLIC,))
        
        
        ################################################
        # #//////////// Peering connection \\\\\\\\\\\\
        #################################################
            
        #VPC peering connection
        VPC_Peering_connection = ec2.CfnVPCPeeringConnection(
            self, "VPCPeeringConnection",
            peer_vpc_id=vpc_managementserver.vpc_id,
            vpc_id=vpc_webserver.vpc_id,)
        
        #Routing table for the private webserver 
        webprivate_subnet_count = 0
        for subnet in vpc_webserver.private_subnets:
            webprivate_subnet_count += 1
            ec2.CfnRoute(self, "web_to_admin_private" + str(webprivate_subnet_count),
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block="10.20.20.0/24",
                vpc_peering_connection_id=VPC_Peering_connection.ref,)
        
        #Routing table for the public webserver   
        web_subnet_count = 0
        for web_subnet in vpc_webserver.public_subnets:
            web_subnet_count += 1
            ec2.CfnRoute(self, "web_to_admin_public" + str(web_subnet_count),
                route_table_id = web_subnet.route_table.route_table_id,
                destination_cidr_block = '10.20.20.0/24',
                vpc_peering_connection_id = VPC_Peering_connection.ref,)
        
        #Routing table for the adminserver
        man_subnet_count = 0    
        for man_subnet in vpc_managementserver.public_subnets:  
            man_subnet_count += 1      
            ec2.CfnRoute(self, "admin_to_web_public" + str(man_subnet_count),
                route_table_id = man_subnet.route_table.route_table_id,
                destination_cidr_block = '10.10.10.0/24', 
                vpc_peering_connection_id = VPC_Peering_connection.ref,)
            
        ################################################
        # #////////////////// KMS \\\\\\\\\\\\\\\\\\\\\\
        #################################################
            
        admin_key = kms.Key(self, "Admin Key",
            enable_key_rotation = True,
            alias = "AdminKey",
            pending_window=Duration.days(10),
            removal_policy = RemovalPolicy.DESTROY)
        self.adminkms_key = admin_key
        
        web_key = kms.Key(self, "Web Key",
            enable_key_rotation = True,
            alias = "WebKey",
            pending_window=Duration.days(10),
            removal_policy = RemovalPolicy.DESTROY)
        self.webkms_key = web_key
        
        vault_key = kms.Key(self, "Vault Key",
            enable_key_rotation = True,
            alias = "VaultKMS_key",
            pending_window=Duration.days(10),
            removal_policy = RemovalPolicy.DESTROY)
        self.vaultkms_key = vault_key
    
        
        ################################################
        # #//////////////// SECURITY \\\\\\\\\\\\\\\\\\\
        #################################################
        
        #//////////// SecurityGroups \\\\\\\\\\\\

        # >>>>>>> SecurityGroup Webserver <<<<<<<<

        # SSH from the admin server.
        SG_webserver.add_ingress_rule(
            ec2.Peer.ipv4("10.20.20.0/24"),
            ec2.Port.tcp(22),
            description ='SSH')

        #HTTP traffic
        SG_webserver.add_ingress_rule(
            ec2.Peer.ipv4("10.20.20.0/24"),
            ec2.Port.tcp(80),
            description = 'HTTP')

        #HTTPS traffic
        SG_webserver.add_ingress_rule(
            ec2.Peer.ipv4("10.20.20.0/24"),
            ec2.Port.tcp(443),
            description = 'HTTPS')

        # >>>>>>> SecurityGroup Managmentserver <<<<<<<<
        
        #SSH traffic
        SG_managementserver.add_ingress_rule(
            # ec2.Peer.any_ipv4(),
            ec2.Peer.ipv4(trusted_ip),
            ec2.Port.tcp(22),
            description = 'SSH',)
        
        #RDP traffic
        SG_managementserver.add_ingress_rule(
            # ec2.Peer.any_ipv4(),
            ec2.Peer.ipv4(trusted_ip),
            ec2.Port.tcp(3389),
            description = 'RDP')
        
        
        #//////////// NACL Webserver \\\\\\\\\\\\
            
        # PUBLIC
        # NACL inbound/outbound HTTP webserver
        NACL_Ws_Public.add_entry(
            id = "Web HTTP inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 100,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
     
        NACL_Ws_Public.add_entry(
            id = "Web HTTP outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 100,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL inbound/outbound HTTPS webserver
        NACL_Ws_Public.add_entry(
            id = 'Web HTTPS inbound',
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 110,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)

        NACL_Ws_Public.add_entry(
            id = 'Web HTTPS outbound',
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 110,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        #Inbound SSH rule for the private webserver NACL.
        NACL_Ws_Public.add_entry(
            id = "Web Inbound SSH traffic",
            # cidr = ec2.AclCidr.any_ipv4(),
            cidr = ec2.AclCidr.ipv4('10.20.20.0/24'), 
            rule_number = 120,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_Ws_Public.add_entry(
            id="Allow ephemeral from anywhere",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=130,
            traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )
        
        NACL_Ws_Public.add_entry(
            id="Allow ephemeral to anywhere",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=130,
            traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )
        
        # PRIVATE
        #Inbound SSH rule for the private webserver NACL.
        NACL_Ws_Private.add_entry(
            id = "PWeb Inbound SSH traffic",
            # cidr = ec2.AclCidr.any_ipv4(),
            cidr = ec2.AclCidr.ipv4('10.20.20.0/24'), 
            rule_number = 100,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_Ws_Private.add_entry(
            id="Allow HTTP inside VPC NACL",
            cidr=ec2.AclCidr.ipv4('10.20.20.0/24'),
            rule_number=110,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_Ws_Private.add_entry(
            id="Allow ephemeral from Internet NACL",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=120,
            traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_Ws_Private.add_entry(
            id="Allow HTTP to anywhere",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=130,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_Ws_Private.add_entry(
            id="Allow HTTPS to anywhere",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=140,
            traffic=ec2.AclTraffic.tcp_port(443),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_Ws_Private.add_entry(
            id="Allow ephemeral to anywhere",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=150,
            traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )
        
        #//////////// NACL Managementserver\\\\\\\\\\\\
        
        NACL_man.add_entry(
            id="Allow SSH inbound from admin pc",
            cidr=ec2.AclCidr.ipv4('10.10.10.0/24'),
            rule_number=100,
            traffic=ec2.AclTraffic.tcp_port(22),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_man.add_entry(
            id="Allow SSH outbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=100,
            traffic=ec2.AclTraffic.tcp_port(22),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_man.add_entry(
            id="Allow Ephemeral inbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=110,
            traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_man.add_entry(
            id="Allow Ephemeral outbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=110,
            traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_man.add_entry(
            id="Allow RDP inbound",
            cidr=ec2.AclCidr.ipv4('10.10.10.0/24'),
            rule_number=120,
            traffic=ec2.AclTraffic.tcp_port(3389),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_man.add_entry(
            id="Allow RDP outbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=120,
            traffic=ec2.AclTraffic.tcp_port(3389),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_man.add_entry(
            id="Allow HTTP inbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=130,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_man.add_entry(
            id="Allow HTTP outbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=130,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_man.add_entry(
            id="Allow HTTPS inbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=140,
            traffic=ec2.AclTraffic.tcp_port(443),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        NACL_man.add_entry(
            id="Allow HTTPS outbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=140,
            traffic=ec2.AclTraffic.tcp_port(443),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )
            
        # #//////////// Key Pair \\\\\\\\\\\\\
        
        kpr_project_cloud = ec2.CfnKeyPair(self, "kpr_project_cloud",
            key_name = "KPR_Project_Cloud",)
        

        ##################################################
        # /////////////// S3 User Bucket \\\\\\\\\\\\\\\\
        ##################################################
        
        Bucket = s3.Bucket(
            self, "userdata_client_test", 
            bucket_name = "bucket-for-userdata", 
            removal_policy = RemovalPolicy.DESTROY,
            encryption = s3.BucketEncryption.S3_MANAGED,
            enforce_ssl = True,
            auto_delete_objects = True)
        
        self.user_data_upload = s3deploy.BucketDeployment(
            self, "DeployWebsite",  
            destination_bucket = Bucket,
            sources = [s3deploy.Source.asset("./project_cloud/user_data")])
        
        #########################################################
         #//////////// EC2 Instance Managementserver \\\\\\\\\\\\
        #########################################################
        
        # ------ AMI Management Server -------
        man_ami = ec2.WindowsImage(
            ec2.WindowsVersion.WINDOWS_SERVER_2022_ENGLISH_FULL_BASE,)
        
        #This is where the user data for the management server is downloaded.
        userdata_manserver = ec2.UserData.for_windows()
        file_script_path_man = userdata_manserver.add_s3_download_command(
            bucket = Bucket,
            bucket_key = "user_data_man.ps1")
        
        userdata_manserver.add_execute_file_command(file_path = file_script_path_man) 
        userdata_manserver.add_execute_file_command(file_path = "./Users/Administrator/")
        
        #This is where the index page is downloaded.
        userdata_manserver.add_s3_download_command(
            bucket = Bucket,
            bucket_key = "KPR_Project_Cloud.pem",
            local_file = "./Users/Administrator/",)

        # EC2 Admin / Management Server
        instance_managementserver = ec2.Instance(
            self, "adminserver",
            instance_type = ec2.InstanceType('t2.micro'),
            machine_image = man_ami,
            vpc = vpc_managementserver,
            security_group = SG_managementserver,
            key_name = "KPR_Project_Cloud",
            user_data = userdata_manserver,
            block_devices = [ec2.BlockDevice(
                device_name = "/dev/sda1",
                volume = ec2.BlockDeviceVolume.ebs(
                    volume_size = 30,
                    encrypted = True,
                    delete_on_termination = True,
                    kms_key = admin_key,
                )
            )]
        )
        
        instance_managementserver.user_data.add_commands("<powershell>",
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
            "Start-Service ssh-agent",
            "Start-Service sshd")

        # userdata_manserver = ec2.CloudFormationInit.from_elements(
        #     ec2.InitCommand.argv_command([
        #         'powershell.exe',
        #         '-command',
        #         'Set-ExecutionPolicy RemoteSigned -Force']),)
        
        
         ##################################################
        #  #//////////// EC2 Instance Webserver \\\\\\\\\\\\
        # ###################################################     

        # --- AMI Webserver ---
        web_ami = ec2.MachineImage.latest_amazon_linux(
            generation = ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            edition = ec2.AmazonLinuxEdition.STANDARD,
            virtualization = ec2.AmazonLinuxVirt.HVM,
            storage = ec2.AmazonLinuxStorage.GENERAL_PURPOSE,)
        
        #This is where the user data for the webserver is downloaded.
       
        # file_script_path = userdata_webserver.add_s3_download_command(
        #     bucket = Bucket,
        #     bucket_key = "user_data.sh",)

        # userdata_webserver.add_execute_file_command(file_path = file_script_path) 

        # #This is where the index page is downloaded.
        # userdata_webserver.add_s3_download_command(
        #     bucket = Bucket,
        #     bucket_key = "index.html",
        #     local_file = "/var/www/html/",)

        # userdata_webserver.add_commands("chmod 755 -R /var/www/html/")

        # userdata_webserver.add_execute_file_command(file_path = "/var/www/html/")
        
        
        
        userdata_webserver = ec2.UserData.for_linux()
        file_script_path = userdata_webserver.add_s3_download_command(
            bucket=Bucket,
            bucket_key="user_data.sh",
        )

        userdata_webserver.add_execute_file_command(file_path=file_script_path)

        instance_webserver = ec2.Instance(
            self, 'webserver',
            instance_type = ec2.InstanceType('t2.micro'),
            machine_image = web_ami,
            vpc = vpc_webserver,
            security_group = SG_webserver,
            key_name = "KPR_Project_Cloud", 
            user_data = userdata_webserver,
            block_devices = [ec2.BlockDevice(
                device_name = "/dev/xvda",
                volume = ec2.BlockDeviceVolume.ebs(
                    volume_size = 8,
                    encrypted = True,
                    delete_on_termination = True,
                    kms_key = web_key,
                ))
            ]
        ) 
        
        ##################################################
        # /////////////// Auto Scaling \\\\\\\\\\\\\\\\
        ##################################################
        
        #User data webserver
        # userdata_webserver = ec2.UserData.for_linux()
        
        
        # #  #//////////// EC2 Instance Launch Template \\\\\\\\\\\\ 
        
        # launchtemplaterole = iam.Role(self, "Launch Template Role",
        #     assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),)

        # self.launch_template = ec2.LaunchTemplate(self, "launchTemplate",
        #     launch_template_name="web_server_template",
        #     instance_type=ec2.InstanceType("t3.nano"),
        #     machine_image=ec2.MachineImage.latest_amazon_linux(
        #         generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2),
        #     security_group = SG_webserver,
        #     key_name = "KPR_Project_Cloud",
        #     role = launchtemplaterole,
        #     user_data = userdata_webserver,
        #     block_devices = [ec2.BlockDevice(
        #         device_name = "/dev/xvda",
        #         volume = ec2.BlockDeviceVolume.ebs(
        #             volume_size = 8,
        #             encrypted = True,
        #             delete_on_termination = True,
        #             kms_key = web_key,
        #             )
        #         )
        #     ],
        # )
        
        # # create and configure the auto scaling group
        # self.as_group = autoscaling.AutoScalingGroup(
        #     self, "Auto Scaling_Group",
        #     vpc=vpc_webserver,
        #     vpc_subnets=ec2.SubnetSelection(
        #         subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
        #     launch_template=self.launch_template,
        #     min_capacity=1,
        #     max_capacity=3,)
        
        # self.as_group.scale_on_cpu_utilization(
        #     "cpu auto scaling",
        #     target_utilization_percent=80,)
        
        # self.elb = elb.ApplicationLoadBalancer(
        #     self, "Application Load Balancer",
        #     vpc=vpc_webserver,
        #     security_group = SG_webserver,
        #     internet_facing=True,)
        
        # http_listener = self.elb.add_listener(
        #     "HTTP listener",
        #     port=80,
        #     open=True,)
        
        # web_target_group = http_listener.add_targets(
        #     "ASG webserver",
        #     port=80,
        #     targets=[self.as_group],
        #     health_check=elb.HealthCheck(
        #         enabled=True,),)
        
        # S3 Read Perms

        # Bucket.grant_read(launchtemplaterole)
        Bucket.grant_read(instance_webserver)
        Bucket.grant_read(instance_managementserver)

        # file_script_path = self.launch_template.user_data.add_s3_download_command(
        #     bucket=Bucket,
        #     bucket_key="user_data.sh",)

        # self.launch_template.user_data.add_execute_file_command(file_path=file_script_path)
        
        #         # Only direct SSH connections to the admin server is allowed.
        # SG_webserver.connections.allow_from(instance_managementserver,
        #     port_range = ec2.Port.tcp(22),)
        
        # ud_policy = ud_bucket.grant_read(launchTemp.role)
        # ud_path = launchTemp.user_data.add_s3_download_command(bucket = ud_bucket, bucket_key = "user_data.sh")
        # ud_exe = launchTemp.user_data.add_execute_file_command(file_path = ud_path)
        
        # # SSL Certificate ARN
        # arn = "arn:aws:acm:eu-central-1:663303000432:certificate/7a324a63-01ba-438c-b7a6-95b6b4e4aecb"

        # # call the certificate itself
        # certificate = acm.Certificate.from_certificate_arn(self, "SSL Cert", arn)
        
        # >>>>>>>>>>> BACK UP PLAN WEBSERVER <<<<<<<<<<<<<<<
    
        # # Created vault
        # self.bckp_vault = backup.BackupVault(
        #     self, 'WebserverBV',
        #     encryption_key = vault_key,
        #     removal_policy = RemovalPolicy.DESTROY,
        #     )

        # # Created plan
        # self.bckp_plan = backup.BackupPlan(
        #     self, 'DailyBP',
        #     backup_vault=self.bckp_vault,
        #     )


        # # Back up instance webserver
        # self.bckp_plan.add_selection('selection',
        #     resources=[
        #         backup.BackupResource.from_ec2_instance(instance_webserver),
        #         ],
        #     allow_restores=True,
        #     )
        
        # # Rules added for the Back up plan. 
        # self.bckp_plan.add_rule(backup.BackupPlanRule(
        #     enable_continuous_backup=True,
        #     delete_after=Duration.days(7),
        #     schedule_expression=events.Schedule.cron(
        #         hour="17",
        #         minute="1",
        #         ))
        # )
        
        
        #  # create and configure the auto scaling group
        # self.as_group = autoscaling.AutoScalingGroup(
        #     self, "Auto_Scaling_Group",
        #     vpc=self.vpc_webserver,
        #     vpc_subnets = ec2.SubnetSelection(subnet_type = ec2.SubnetType.PRIVATE_WITH_EGRESS),
        #     launch_template = self.launch_template,
        #     min_capacity=1,
        #     max_capacity=3,
        #     health_check = autoscale.HealthCheck.elb(grace = Duration.minutes(5)))
        
        
