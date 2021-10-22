from checkov.terraform.checks.provider.base_check import BaseProviderCheck
from checkov.common.models.enums import CheckResult, CheckCategories



class eksAuthCheckProvider(BaseProviderCheck):
    def __init__(self):
        name = "No token is used for EKS Authentication"
        id = "CKV_AWS_GS_1"
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