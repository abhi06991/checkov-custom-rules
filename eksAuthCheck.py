from lark import Token
import pprint
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.provider.base_check import BaseProviderCheck
from checkov.common.models.enums import CheckResult, CheckCategories



class eksAuthCheckProvider(BaseProviderCheck):
    def __init__(self):
        name = "No token is used for EKS Authentication"
        id = "CKV_GS_AWS_10001"
        supported_provider = ['kubernetes']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_provider=supported_provider)


    def scan_provider_conf(self,conf):
        if 'token' in conf.keys():
            token = conf['token']
            if not token:
                return CheckResult.FAILED
            else:
                return CheckResult.PASSED
        else:
            return CheckResult.FAILED

scanner = eksAuthCheckProvider()










# class eksAuthCheckResource(BaseResourceCheck):
#     def __init__(self):
#         name = "Resource does not provide a token for EKS Authentication"
#         id = "CKV_GS_AWS_10001"
#         supported_resources = ['*']
#         # CheckCategories are defined in models/enums.py
#         categories = [CheckCategories.KUBERNETES]
#         super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

#     def scan_resource_conf(self, conf):
#         pass
#         # if 'policy' in conf.keys():
#         #     kmsAction = conf['policy'][0]['Action'].strip()
#         #     principalValue = conf['policy'][0]['Principal']['AWS']
#         #     print("asdasdasds")
#         #     pprint.pprint(self)
#         #     exit()
#         #     if (kmsAction == 'kms:*'):
#         #         return CheckResult.FAILED
#         #     else:
#         #         return CheckResult.PASSED
#         # else:
#         #     return CheckResult.FAILED


# scanner = eksAuthCheckResource()