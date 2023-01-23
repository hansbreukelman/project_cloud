from aws_cdk import (
    aws_ec2 as ec2,
)

from constructs import Construct  

from requests import get

trusted_ip = get('https://api.ipify.org').text + '/32'

class NaclConstruct(Construct):

    def __init__(self, scope: Construct, construct_id: str, vpc_webserver, vpc_managementserver, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
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
            # cidr = ec2.AclCidr.any_ipv4(),
            cidr = ec2.AclCidr.ipv4(trusted_ip),
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
            # cidr = ec2.AclCidr.any_ipv4(),
            cidr = ec2.AclCidr.ipv4(trusted_ip),
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
