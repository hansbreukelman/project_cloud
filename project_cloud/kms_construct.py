from aws_cdk import (
    aws_kms as kms,
    RemovalPolicy,
)

from constructs import Construct  

class KmsAdminConstruct(Construct):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
          # >>>>>>>>>>> KMS Module <<<<<<<<<<<<<<

        admin_key = kms.Key(self, "Admin Key",
            enable_key_rotation = True,
            alias = "AdminKey",
            removal_policy = RemovalPolicy.DESTROY)
        self.adminkms_key = admin_key
        
class KmsWebConstruct(Construct):
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        web_key = kms.Key(self, "Web Key",
            enable_key_rotation = True,
            alias = "WebKey",
            removal_policy = RemovalPolicy.DESTROY)
        self.webkms_key = web_key


class KmsVaultConstruct(Construct):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        vault_key = kms.Key(self, "Vault Key",
            enable_key_rotation = True,
            alias = "VaultKMS_key",
            removal_policy = RemovalPolicy.DESTROY)
        self.vaultkms_key = vault_key