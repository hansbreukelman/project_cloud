from project_cloud.nacl_construct import NaclConstruct
from project_cloud.kms_construct import KmsAdminConstruct, KmsVaultConstruct, KmsWebConstruct

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
)

import boto3

from constructs import Construct

from requests import get

trusted_ip = get('https://api.ipify.org').text + '/32'

class ProjectCloudStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs) 
        
        ################################################
         #////////////// VPC Webserver \\\\\\\\\\\\\\\\\
        ################################################
        
        self.vpc_webserver = ec2.Vpc(self, "VPC_1",
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

        
        ################################################
        #//////////// VPC Managementserver \\\\\\\\\\\\
        ################################################
        
        self.vpc_managementserver = ec2.Vpc( self, "VPC_2",
            ip_addresses=ec2.IpAddresses.cidr("10.20.20.0/24"),
            vpc_name = "vpc_managementserver",
            nat_gateways = 0,
            availability_zones = ["eu-central-1a", "eu-central-1b"],
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public_man", 
                    cidr_mask=25, 
                    subnet_type=ec2.SubnetType.PUBLIC),])
        
        
        ################################################
        # #//////////// Peering connection \\\\\\\\\\\\
        #################################################
            
         #VPC peering connection
        VPC_Peering_connection = ec2.CfnVPCPeeringConnection(
            self, "VPCPeeringConnection",
            peer_vpc_id=self.vpc_managementserver.vpc_id,
            vpc_id=self.vpc_webserver.vpc_id,)
        
        man_subnet_count = 0    
        for man_subnet in self.vpc_managementserver.public_subnets:  
            man_subnet_count += 1      
            ec2.CfnRoute(self, "Web Private Subnet Route Table" + str(man_subnet_count),
                route_table_id = man_subnet.route_table.route_table_id,
                destination_cidr_block = '10.20.20.0/24',
                vpc_peering_connection_id = VPC_Peering_connection.ref,)
        
        web_subnet_count = 0
        #Routing table for the adminserver
        for web_subnet in self.vpc_webserver.public_subnets:
            web_subnet_count += 1
            ec2.CfnRoute(
                self, 'Management Route Table' + str(web_subnet_count),
                route_table_id = web_subnet.route_table.route_table_id,
                destination_cidr_block = '10.10.10.0/24', 
                vpc_peering_connection_id = VPC_Peering_connection.ref,)
            
            
        ################################################
        # #//////////////// SECURITY \\\\\\\\\\\\\\\\\\\
        #################################################
    
        #NetworkACL
        self.networkacl = NaclConstruct(
            self, 'Network ACL',
            vpc_webserver = self.vpc_webserver,
            vpc_managementserver = self.vpc_managementserver,
        )  

        #//////////// SecurityGroups \\\\\\\\\\\\
        
        # SecurityGroup Webserver
        SG_webserver = ec2.SecurityGroup(self, "SGwebserver",
            vpc = self.vpc_webserver,
            description = "SGWebServer",
            allow_all_outbound = True,)

        # SSH from the admin server.
        SG_webserver.add_ingress_rule(
            ec2.Peer.ipv4("10.10.10.0/24"),
            ec2.Port.tcp(22),
            description ='SSH')

        #HTTP traffic
        SG_webserver.add_ingress_rule(
            ec2.Peer.ipv4("10.10.10.0/24"),
            ec2.Port.tcp(80),
            escription = 'HTTP')

        #HTTPS traffic
        SG_webserver.add_ingress_rule(
            ec2.Peer.ipv4("10.10.10.0/24"),
            ec2.Port.tcp(443),
            description = 'HTTPS')

        # SecurityGroup Managmentserver
        SG_managementserver = ec2.SecurityGroup(self, "SGmanagementserver",
            vpc = self.vpc_managementserver,
            description = "SGManServer",
            allow_all_outbound = True,)
        
        #SSH traffic
        SG_managementserver.add_ingress_rule(
            # ec2.Peer.any_ipv4(),
            ec2.Peer.ipv4(trusted_ip),
            ec2.Port.tcp(22),
            escription = 'SSH',)
        
        #RDP traffic
        SG_managementserver.add_ingress_rule(
            # ec2.Peer.any_ipv4(),
            ec2.Peer.ipv4(trusted_ip),
            ec2.Port.tcp(3389),
            description = 'RDP')
        
        # /////////////// KMS keys \\\\\\\\\\\\\\\\
            
        # vault_key = KmsVaultConstruct(self, 'KMS_vault',)
        admin_key = KmsAdminConstruct(self, 'KMS_admin',)
        web_key = KmsWebConstruct(self, 'KMS_web',)
            
        # #//////////// Key Pair \\\\\\\\\\\\\
        
        self.kpr_project_cloud = ec2.CfnKeyPair(self, "kpr_project_cloud",
            key_name = "project_cloud_KPR",)
        

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
            sources = [s3deploy.Source.asset("./project_cloud")],  
            destination_bucket = Bucket,)
        
    
        
        ##################################################
        # /////////////// Auto Scaling \\\\\\\\\\\\\\\\
        ##################################################
        
        #User data webserver
        userdata_webserver = ec2.UserData.for_linux()
        
        
        #  #//////////// EC2 Instance Launch Template \\\\\\\\\\\\ 
        
        launchtemplaterole = iam.Role(self, "Launch Template Role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),)

        # Launch Template
        self.launch_template = ec2.LaunchTemplate(self, "launchTemplate",
            launch_template_name="web_server_template",
            instance_type=ec2.InstanceType("t2.micro"),
            machine_image=ec2.MachineImage.latest_amazon_linux(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2),
            security_group = SG_webserver,
            key_name = "project_cloud_KPR",
            role = launchtemplaterole,
            user_data = userdata_webserver,
            block_devices = [ec2.BlockDevice(
                device_name = "/dev/xvda",
                volume = ec2.BlockDeviceVolume.ebs(
                    volume_size = 8,
                    encrypted = True,
                    delete_on_termination = True,
                    kms_key = web_key,
                    )
                )
            ],
        )
        
        # create and configure the auto scaling group
        self.as_group = autoscaling.AutoScalingGroup(
            self, "Auto Scaling_Group",
            vpc=self.vpc_webserver,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            launch_template=self.launch_template,
            min_capacity=1,
            max_capacity=3,)
        
        self.as_group.scale_on_cpu_utilization(
            "cpu auto scaling",
            target_utilization_percent=80,)
        
        self.elb = elb.ApplicationLoadBalancer(
            self, "Application Load Balancer",
            vpc=self.vpc_webserver,
            internet_facing=True,
            security_group = SG_webserver,)
        
        # LOAD BALANCER
        self.elb = elb.ApplicationLoadBalancer(
            self, "Application Load Balancer",
            vpc=self.vpc_webserver,
            security_group = SG_webserver,
            internet_facing=True,)
        
        http_listener = self.elb.add_listener(
            "HTTP listener",
            port=80,
            open=True,)
        
        web_target_group = http_listener.add_targets(
            "ASG webserver",
            port=80,
            targets=[self.as_group],
            health_check=elb.HealthCheck(
                enabled=True,),)
        
        # S3 Read Perms

        Bucket.grant_read(launchtemplaterole)

        file_script_path = self.launch_template.user_data.add_s3_download_command(
            bucket=Bucket,
            bucket_key="user_data.sh",)

        self.launch_template.user_data.add_execute_file_command(file_path=file_script_path)
    
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
            bucket_key = "project_cloud_KPR.pem",
            local_file = "./Users/Administrator/",)

        # EC2 Admin / Management Server
        instance_managementserver = ec2.Instance(
            self, "adminserver",
            instance_type = ec2.InstanceType('t2.micro'),
            machine_image = man_ami,
            vpc = self.vpc_managementserver,
            security_group = SG_managementserver,
            key_name = 'project_cloud_KPR',
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

        userdata_manserver = ec2.CloudFormationInit.from_elements(
            ec2.InitCommand.argv_command([
                'powershell.exe',
                '-command',
                'Set-ExecutionPolicy RemoteSigned -Force']),)
        
        asg_userdata = self.as_group.user_data.add_s3_download_command(bucket=Bucket,bucket_key="user_data.sh")
        self.as_group.user_data.add_execute_file_command(file_path=asg_userdata)
        
        # #This is where the user data for the webserver is downloaded.
        # file_script_path = userdata_webserver.add_s3_download_command(bucket = Bucket,bucket_key = "user_data.sh",)
        # userdata_webserver.add_execute_file_command(file_path = file_script_path) 

        # #This is where the index page is downloaded.
        # userdata_webserver.add_s3_download_command(
        #     bucket = Bucket,
        #     bucket_key = "index.html",
        #     local_file = "/var/www/html/",)

        # userdata_webserver.add_commands("chmod 755 -R /var/www/html/")

        # userdata_webserver.add_execute_file_command(file_path = "/var/www/html/")
        
        # ##################################################
        #  #//////////// EC2 Instance Webserver \\\\\\\\\\\\
        # ###################################################     

        # # --- AMI Webserver ---
        # web_ami = ec2.MachineImage.latest_amazon_linux(
        #     generation = ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
        #     edition = ec2.AmazonLinuxEdition.STANDARD,
        #     virtualization = ec2.AmazonLinuxVirt.HVM,
        #     storage = ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
        # )
        
        # #This is where the user data for the webserver is downloaded.
        # userdata_webserver = ec2.UserData.for_linux()
        # file_script_path = userdata_webserver.add_s3_download_command(
        #     bucket = Bucket,
        #     bucket_key = "user_data.sh",            
        # )

        # userdata_webserver.add_execute_file_command(file_path = file_script_path) 

        # #This is where the index page is downloaded.
        # userdata_webserver.add_s3_download_command(
        #     bucket = Bucket,
        #     bucket_key = "index.html",
        #     local_file = "/var/www/html/",
        # )

        # userdata_webserver.add_commands("chmod 755 -R /var/www/html/")

        # userdata_webserver.add_execute_file_command(file_path = "/var/www/html/")

        # instance_webserver = ec2.Instance(
        #     self, 'webserver',
        #     instance_type = ec2.InstanceType('t2.micro'),
        #     machine_image = web_ami,
        #     vpc = self.vpc_webserver,
        #     security_group = SG_webserver,
        #     key_name = 'project_cloud_KPR', 
        #     user_data = userdata_webserver,
        #     block_devices = [ec2.BlockDevice(
        #         device_name = "/dev/xvda",
        #         volume = ec2.BlockDeviceVolume.ebs(
        #             volume_size = 8,
        #             encrypted = True,
        #             delete_on_termination = True,
        #             kms_key = web_key,
        #         ))
        #     ]
        # ) 
        
        #This is where I set a permission to allow the servers to read my s3 Bucket.
        
        # Bucket.grant_read(instance_webserver)
        
        
        # asg_userdata = self.as_group.user_data.add_s3_download_command(
        #     bucket=Bucket,
        #     bucket_key="user_data.sh"
        # )

        # # execute the userdata file
        # self.as_group.user_data.add_execute_file_command(file_path=asg_userdata)
        
        
        # Only direct SSH connections to the admin server is allowed.
        SG_webserver.connections.allow_from(instance_managementserver,
            port_range = ec2.Port.tcp(22),)
        
        # S3 Read Perms

        Bucket.grant_read(self.launch_template)
        
        Bucket.grant_read(instance_managementserver)
        
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
        
        
