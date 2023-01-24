from .nacl_construct import NaclConstruct
from .kms_construct import KmsAdminConstruct, KmsWebConstruct, KmsVaultConstruct
from aws_cdk import (
    RemovalPolicy,
    Duration,
    Stack,
    aws_ec2 as ec2,
    aws_s3 as s3,
    RemovalPolicy,
    aws_s3_deployment as s3deploy,
    aws_s3_assets as Asset,
    aws_iam as iam,
    aws_kms as kms,
    aws_backup as backup,
    aws_events as events,
    aws_elasticloadbalancingv2 as elb,
    aws_autoscaling as autoscaling,
    aws_certificatemanager as acm,
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
        
        self.vpc_webserver = ec2.Vpc(
            self, "VPC_1",
            ip_addresses=ec2.IpAddresses.cidr("10.10.10.0/24"),
            nat_gateways = 1,
            availability_zones = ["eu-central-1a", "eu-central-1b", "eu-central-1c"],
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="private_web", 
                    cidr_mask=26, 
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
                ec2.SubnetConfiguration(
                    name="public_web", 
                    cidr_mask=28, 
                    subnet_type=ec2.SubnetType.PUBLIC)
            ]
        ) 
        
        
        ################################################
        #//////////// VPC Managementserver \\\\\\\\\\\\
        ################################################
        
        self.vpc_managementserver = ec2.Vpc(
            self, "VPC_2",
            ip_addresses=ec2.IpAddresses.cidr("10.20.20.0/24"),
            nat_gateways=0,
            availability_zones=['eu-central-1b'],
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public_man", 
                    cidr_mask=26, 
                    subnet_type=ec2.SubnetType.PUBLIC),
                ]
        )
        
        
        ################################################
        # #//////////// Peering connection \\\\\\\\\\\\
        #################################################
            
         #VPC peering connection
        VPC_Peering_connection = ec2.CfnVPCPeeringConnection(
            self, "VPCPeeringConnection",
            peer_vpc_id=self.vpc_managementserver.vpc_id,
            vpc_id=self.vpc_webserver.vpc_id,
        )
        
        man_subnet_count = 0
        #Routing table for the adminserver
        for subnet in self.vpc_managementserver.public_subnets:
            man_subnet_count += 1
            ec2.CfnRoute(
                self, 'Management Route Table' + str(man_subnet_count),
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block="10.10.10.0/24", 
                vpc_peering_connection_id=VPC_Peering_connection.attr_id)

        web_subnet_count = 0
        for web_subnet in self.vpc_webserver.private_subnets:  
            web_subnet_count += 1      
            ec2.CfnRoute(self, "Web Private Subnet Route Table" + str(web_subnet_count),
                route_table_id = web_subnet.route_table.route_table_id,
                destination_cidr_block = "10.20.20.0/24",
                vpc_peering_connection_id = VPC_Peering_connection.attr_id)
        
        # #Routing table for the webserver
        # for subnet in self.vpc_webserver.public_subnets:
        #     name_count += 1
        #     ec2.CfnRoute(
        #         self, 'Web Public Route Table' + str(name_count),
        #         route_table_id=subnet.route_table.route_table_id,
        #         destination_cidr_block="10.20.20.0/24", 
        #         vpc_peering_connection_id=VPC_Peering_connection.ref,)
            
            
        #NetworkACL
        networkacl = NaclConstruct(
            self, 'Network ACL',
            vpc_webserver = self.vpc_webserver,
            vpc_managementserver = self.vpc_managementserver,
        )  
            

        #//////////// SecurityGroups \\\\\\\\\\\\
        
        # SecurityGroup Webserver
        SG_webserver = ec2.SecurityGroup(self, "SGwebserver",
            vpc = self.vpc_webserver,
            security_group_name = "SGWebServer",
            allow_all_outbound = True,
        )

        #HTTP traffic
        SG_webserver.add_ingress_rule(
            ec2.Peer.ipv4("10.10.10.0/24"),
            ec2.Port.tcp(80),
        )

        #HTTPS traffic
        SG_webserver.add_ingress_rule(
            ec2.Peer.ipv4("10.10.10.0/24"),
            ec2.Port.tcp(443),
        )

        # SSH from the admin server.
        SG_webserver.add_ingress_rule(
            ec2.Peer.ipv4("10.10.10.0/24"),
            ec2.Port.tcp(22)
        )
        
        # SecurityGroup Managmentserver
        SG_managementserver = ec2.SecurityGroup(self, "SGmanagementserver",
            vpc = self.vpc_managementserver,
            security_group_name = "SGManServer",
            allow_all_outbound = True,
        )
        
        #RDP traffic
        SG_managementserver.add_ingress_rule(
            # ec2.Peer.any_ipv4(),
            ec2.Peer.ipv4(trusted_ip),
            ec2.Port.tcp(3389),
        )
            
        #SSH traffic
        SG_managementserver.add_ingress_rule(
            # ec2.Peer.any_ipv4(),
            ec2.Peer.ipv4(trusted_ip),
            ec2.Port.tcp(22),
        )
        
        # #//////////// Key Pair \\\\\\\\\\\\\
        
        self.kpr_project_cloud = ec2.CfnKeyPair(self, "kpr_project_cloud",
            key_name = "project_cloud_KPR",
        )
        

        ##################################################
        # /////////////// S3 User Bucket \\\\\\\\\\\\\\\\
        ##################################################
        
        Bucket = s3.Bucket(
            self, "userdata_client_test", 
            bucket_name = "bucket-for-userdata", 
            removal_policy = RemovalPolicy.DESTROY,
            encryption = s3.BucketEncryption.S3_MANAGED,
            enforce_ssl = True,
            auto_delete_objects = True
        )
        
        self.user_data_upload = s3deploy.BucketDeployment(
            self, "DeployWebsite",
            sources = [s3deploy.Source.asset("./project_cloud")],  
            destination_bucket = Bucket,
        )
        
        
        ##################################################
         #//////////// EC2 Instance Webserver \\\\\\\\\\\\
        ###################################################     
        
        web_key = KmsWebConstruct(
            self, 'KMS_web',
        )

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
            local_file = "/var/www/html/",
        )

        userdata_webserver.add_commands("chmod 755 -R /var/www/html/")

        userdata_webserver.add_execute_file_command(file_path = "/var/www/html/")

        instance_webserver = ec2.Instance(
            self, 'webserver',
            instance_type = ec2.InstanceType('t2.micro'),
            machine_image = web_ami,
            vpc = self.vpc_webserver,
            security_group = SG_webserver,
            key_name = 'project_cloud_KPR', 
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
            
        
        #########################################################
         #//////////// EC2 Instance Managementserver \\\\\\\\\\\\
        #########################################################
        
        admin_key = KmsAdminConstruct(
            self, 'KMS_admin',
        )
        
        # ------ AMI Management Server -------
        man_ami = ec2.WindowsImage(
            ec2.WindowsVersion.WINDOWS_SERVER_2022_ENGLISH_FULL_BASE,
        )
        
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
            local_file = "./Users/Administrator/",
        )

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
                'Set-ExecutionPolicy RemoteSigned -Force'
                ]),
            )

        #This is where I set a permission to allow the servers to read my s3 Bucket.
        Bucket.grant_read(instance_webserver)
        Bucket.grant_read(instance_managementserver)
        
        # Bucket.grant_read()
        
        #Only direct SSH connections to the admin server is allowed.
        # SG_webserver.connections.allow_from(instance_managementserver,
        #     port_range = ec2.Port.tcp(22),
        # )
        
         # >>>>>> LOAD BALANCER <<<<<<<
        
        # Create the load balancer in a VPC. 'internetFacing' is 'false'
        # by default, which creates an internal load balancer.
        self.elb = elb.ApplicationLoadBalancer(
            self, "Application Load Balancer",
            vpc=self.vpc_webserver,
            internet_facing=True,
        )
        self.elb.add_redirect()
        
        # >>>>>>>>>>>> Auto Scaling <<<<<<<<<<<<<<

        # Launch Template
        self.launch_temp = ec2.LaunchTemplate(
            self, "Launch template",
            launch_template_name="web_server_template",
            instance_type=ec2.InstanceType("t2.micro"),
            machine_image=ec2.MachineImage.latest_amazon_linux(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2),
            key_name="project_cloud_KPR",
            role = iam.Role(
                self, "role", 
                assumed_by= iam.ServicePrincipal("ec2.amazonaws.com")),
            user_data = ec2.UserData.for_linux(),
            security_group=SG_webserver,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(
                        volume_size=8,
                        encrypted=True,
                        delete_on_termination=True,    
                    )
                )
            ]
        )
        
        # ud_policy = ud_bucket.grant_read(launchTemp.role)
        # ud_path = launchTemp.user_data.add_s3_download_command(bucket = ud_bucket, bucket_key = "user_data.sh")
        # ud_exe = launchTemp.user_data.add_execute_file_command(file_path = ud_path)
        
        # create and configure the auto scaling group
        as_group = autoscaling.AutoScalingGroup(
            self, "Auto_Scaling_Group",
            vpc=self.vpc_webserver,
            min_capacity=1,
            max_capacity=3,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC
            ),
            launch_template=self.launch_temp,
        )
        
        # scaling policy
        as_group.scale_on_cpu_utilization(
            "cpu auto scaling",
            target_utilization_percent=80,
        )
        
        # # SSL Certificate ARN
        # arn = "arn:aws:acm:eu-central-1:663303000432:certificate/7a324a63-01ba-438c-b7a6-95b6b4e4aecb"

        # # call the certificate itself
        # certificate = acm.Certificate.from_certificate_arn(self, "SSL Cert", arn)
        
        
        # https_listener = self.elb.add_listener(
        #     "Listener for HTTPS",
        #     port=443,
        #     open=True,
        #     ssl_policy=elb.SslPolicy.FORWARD_SECRECY_TLS12,
        #     certificates=[certificate],
        # )

        # asg_target_group = https_listener.add_targets(
        #     "ASG webserver",
        #     port=80,
        #     targets=[self.as_group],
        #     health_check=elb.HealthCheck(
        #         enabled=True,
        #         port="80",
        #     ),
        #     stickiness_cookie_duration=Duration.minutes(5),
        #     stickiness_cookie_name="pbc",
        # )

        asg_userdata = as_group.user_data.add_s3_download_command(
            bucket=Bucket,
            bucket_key="user_data.sh"
        )

        # execute the userdata file
        as_group.user_data.add_execute_file_command(file_path=asg_userdata)
        
        # >>>>>>>>>>> BACK UP PLAN WEBSERVER <<<<<<<<<<<<<<<
        
        vault_key = KmsVaultConstruct(
            self, 'KMS_vault',
        )
        
        # Created vault
        self.bckp_vault = backup.BackupVault(
            self, 'WebserverBV',
            encryption_key = vault_key,
            removal_policy = RemovalPolicy.DESTROY,
            )

        # Created plan
        self.bckp_plan = backup.BackupPlan(
            self, 'DailyBP',
            backup_vault=self.bckp_vault,
            )

        # Back up instance webserver
        self.bckp_plan.add_selection('selection',
            resources=[
                backup.BackupResource.from_ec2_instance(instance_webserver),
                ],
            allow_restores=True,
            )
        
        # Rules added for the Back up plan. 
        self.bckp_plan.add_rule(backup.BackupPlanRule(
            enable_continuous_backup=True,
            delete_after=Duration.days(7),
            schedule_expression=events.Schedule.cron(
                hour="5",
                minute="0",
                ))
            )
