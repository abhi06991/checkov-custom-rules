import pprint
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class AWSInternetGatewayCheck(BaseResourceCheck):
    def __init__(self):
        name = "VPC Endpoint policy not defined."
        id = "CKV_GS_AWS_10122343"
        supported_resources = ['aws_vpc_endpoint']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'policy' in conf.keys():
            policyDefined = conf['policy']
            if policyDefined[0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        else:
            return CheckResult.FAILED

scanner = AWSInternetGatewayCheck()
