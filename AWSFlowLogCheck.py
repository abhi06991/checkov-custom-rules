from lark import Token
import pprint
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class AWSFlowLogCheck(BaseResourceCheck):
    def __init__(self):
        name = "Resource has no traffic log enabled."
        id = "CKV_GS_AWS_10003"
        supported_resources = ['aws_flow_log']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'traffic_type' in conf.keys():
            trafficType = conf['traffic_type'][0]
            pprint.pprint(conf.keys())
            pprint.pprint(type(trafficType))
            if (trafficType != 'ALL'):
                return CheckResult.FAILED
            else:
                return CheckResult.PASSED
        else:
            return CheckResult.FAILED


scanner = AWSFlowLogCheck()
