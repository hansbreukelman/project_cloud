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
            
        # NACL webserver public
        NACL_Ws_Public = ec2.NetworkAcl(
            self, "NACL_Web_Public", 
            vpc = vpc_webserver,
            subnet_selection = ec2.SubnetSelection(
                subnet_type = ec2.SubnetType.PUBLIC))
        
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
        
        # NACL inbound SSH webserver
        NACL_Ws_Public.add_entry(
            id = "Web SSH inbound",
            # cidr = ec2.AclCidr.any_ipv4(),
            cidr = ec2.AclCidr.ipv4('10.20.20.0/24'),
            rule_number = 120,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)

        # NACL inbound/outbound Ephemeral webserver
        NACL_Ws_Public.add_entry(
            id = "Web Ephemeral inbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 130,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_Ws_Public.add_entry(
            id = "Web Ephemeral outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 130,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL inbound/outbound Ephemeral webserver - ipv6
        NACL_Ws_Public.add_entry(
            id = "Web Ephemeral inbound ipv6",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 140,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_Ws_Public.add_entry(
            id = "Web Ephemeral outbound ipv6",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 140,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL inbound/outbound HTTP webserver - ipv6
        NACL_Ws_Public.add_entry(
            id = "Web http inbound ipv6",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 150,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)

        NACL_Ws_Public.add_entry(
            id = "Web http outbound ipv6",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 150,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL inbound/outbound HTTPS webserver - ipv6
        NACL_Ws_Public.add_entry(
            id = "Web https inbound ipv6",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 160,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_Ws_Public.add_entry(
            id = "Web https outbound ipv6",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 160,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        
        # NACL webserver private
        NACL_Ws_Private = ec2.NetworkAcl(
            self, "NACL_Web_Private", 
            vpc = vpc_webserver,
            subnet_selection = ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED))
        
        #Inbound/outbound HTTP rule for the private webserver NACL.
        NACL_Ws_Private.add_entry(
            id = "PWeb Inbound HTTP traffic",
            cidr = ec2.AclCidr.any_ipv4(), 
            rule_number = 100,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_Ws_Private.add_entry(
            id = "PWeb Outbound HTTP traffic",
            cidr = ec2.AclCidr.any_ipv4(), 
            rule_number = 100,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        #Inbound/outbound HTTPS rule for the private webserver NACL.
        NACL_Ws_Private.add_entry(
            id = "PWeb HTTPS traffic",
            cidr = ec2.AclCidr.any_ipv4(), 
            rule_number = 110,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_Ws_Private.add_entry(
            id = "PWeb Outbound HTTPS traffic",
            cidr = ec2.AclCidr.any_ipv4(), 
            rule_number = 110,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        #Inbound/outbound Ephemeral rule for the private webserver NACL.
        NACL_Ws_Private.add_entry(
            id = "PWeb Inbound Ephemeral traffic",
            cidr = ec2.AclCidr.any_ipv4(), 
            rule_number = 120,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_Ws_Private.add_entry(
            id = "PWeb utbound Ephemeral traffic",
            cidr = ec2.AclCidr.any_ipv4(), 
            rule_number = 120,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        #Inbound SSH rule for the private webserver NACL.
        NACL_Ws_Private.add_entry(
            id = "PWeb Inbound SSH traffic",
            cidr = ec2.AclCidr.any_ipv4(), 
            rule_number = 130,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        
        #//////////// NACL Managementserver\\\\\\\\\\\\

        # NACL Managmentserver
        NACL_man = ec2.NetworkAcl(
            self, "NACL_Man", 
            vpc = vpc_managementserver,
            subnet_selection = ec2.SubnetSelection(
                subnet_type = ec2.SubnetType.PUBLIC,
            )
        )
        
        # NACL inbound/outbound SSH Managementserver subnet
        NACL_man.add_entry(
            id = "Man SSH inbound",
            # cidr = ec2.AclCidr.any_ipv4(),
            cidr = ec2.AclCidr.ipv4('10.10.10.0/24'),
            rule_number = 100,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_man.add_entry(
            id = "Man SSH outbound",
            cidr = ec2.AclCidr.ipv4('10.10.10.0/24'),
            rule_number = 100,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW) 
        
        # NACL SSH inbound/outbound trusted IP
        NACL_man.add_entry(
            id = "SSH inbound allow AdminIP",
            cidr = ec2.AclCidr.ipv4(trusted_ip),
            rule_number = 110,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_man.add_entry(
            id = "SSH outbound allow AdminIP",
            cidr = ec2.AclCidr.ipv4(trusted_ip),
            rule_number = 110,
            traffic = ec2.AclTraffic.tcp_port(22),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW) 
        
        # NACL Ephemeral inbound/outbound trusted IP
        NACL_man.add_entry(
            id = 'Inbound Ephemeral allow AdminIP',
            cidr = ec2.AclCidr.ipv4(trusted_ip),
            rule_number = 120,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_man.add_entry(
            id = 'Outbound Ephemeral allow AdminIP',
            cidr = ec2.AclCidr.ipv4(trusted_ip),
            rule_number = 120,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL inbound/outbound RDP Managementserver
        NACL_man.add_entry(
            id = "Man RDP inbound",
            # cidr = ec2.AclCidr.any_ipv4(),
            cidr = ec2.AclCidr.ipv4(trusted_ip),
            rule_number = 130,
            traffic = ec2.AclTraffic.tcp_port(3389),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_man.add_entry(
            id = "Man RDP outbound",
            # cidr = ec2.AclCidr.any_ipv4(),
            cidr = ec2.AclCidr.ipv4(trusted_ip),
            rule_number = 130,
            traffic = ec2.AclTraffic.tcp_port(3389),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL inbound/outbound Ephemeral Managementserver - Subnet Web
        NACL_man.add_entry(
            id = "Man Ephemeral inbound subnet",
            cidr = ec2.AclCidr.ipv4("10.10.10.0/24"),
            rule_number = 140,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_man.add_entry(
            id = "Man Ephemeral outbound subnet",
            cidr = ec2.AclCidr.ipv4("10.10.10.0/24"),
            rule_number = 140,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL inbound/outbound Ephemeral Managementserver - ipv4
        NACL_man.add_entry(
            id = "Man Ephemeral inbound ipv4",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 150,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_man.add_entry(
            id = "Man Ephemeral outbound ipv4",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 150,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL inbound Ephemeral Managementserver - ipv6
        NACL_man.add_entry(
            id = "Man Ephemeral inbound ipv6",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 160,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.INGRESS,
            rule_action = ec2.Action.ALLOW)
        
        NACL_man.add_entry(
            id = "Man Ephemeral outbound ipv6",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 160,
            traffic = ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL outbound HTTP Managementserver - ipv6
        NACL_man.add_entry(
            id = "Man http ipv6 outbound",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 165,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL outbound HTTPS Managementserver - ipv6
        NACL_man.add_entry(
            id = "Man https ipv6 outbound",
            cidr = ec2.AclCidr.any_ipv6(),
            rule_number = 170,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL outbound HTTP Managementserver
        NACL_man.add_entry(
            id = "Man http outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 175,
            traffic = ec2.AclTraffic.tcp_port(80),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
        
        # NACL outbound HTTPS Managementserver
        NACL_man.add_entry(
            id = "Man https outbound",
            cidr = ec2.AclCidr.any_ipv4(),
            rule_number = 180,
            traffic = ec2.AclTraffic.tcp_port(443),
            direction = ec2.TrafficDirection.EGRESS,
            rule_action = ec2.Action.ALLOW)
    

