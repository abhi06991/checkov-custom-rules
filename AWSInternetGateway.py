import pprint
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class AWSInternetGatewayCheck(BaseResourceCheck):
    def __init__(self):
        name = "Internet Gateway is created. Internet Gateway is not allowed."
        id = "CKV_GS_AWS_101223"
        supported_resources = ['aws_internet_gateway']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        pprint.pprint(bool(conf))
        if bool(conf) is False:
            return CheckResult.PASSED
        else:
            return CheckResult.FAILED


scanner = AWSInternetGatewayCheck()
