from constructs import Construct
from aws_cdk import (
    aws_ec2 as ec2,
    Stack,
)

class ProjectCloudStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        #This is the webserver VPC
        vpc_webserver = ec2.Vpc(
            self, "VPC_1",
            ip_addresses=ec2.IpAddresses.cidr("10.10.10.0/24"),
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public", 
                    cidr_mask=26, 
                    subnet_type=ec2.SubnetType.PUBLIC),
                ]
        )   
        
        #This is the managementserver VPC
        vpc_managementserver = ec2.Vpc(
            self, "VPC_2",
            ip_addresses=ec2.IpAddresses.cidr("10.20.20.0/24"),
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public", 
                    cidr_mask=26, 
                    subnet_type=ec2.SubnetType.PUBLIC),
                ]
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

        #--------------Webserver SG-------------------
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

        #--------------Managementserver SG-------------------
        SG_managementserver = ec2.SecurityGroup(self, "SGmanagementserver",
            vpc = vpc_managementserver,
            security_group_name = "SGManServer",
            allow_all_outbound = True,
        )

        #SSH traffic
        SG_managementserver.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(22),
        )

        #RDP traffic
        SG_managementserver.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(3389),
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


