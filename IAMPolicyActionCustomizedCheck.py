from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class IAMPolicyActionCustomizedCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure no IAM policies allow “*” as a statement’s actions"
        id = "CKV_AWS_63_Customized"
        supported_resources = ['aws_iam_policy']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'policy' in conf.keys():
            if 'Statement' in conf['policy'][0]:
                policyStatement = conf['policy'][0]['Statement'][0]
                for index,values in enumerate(policyStatement):
                    if values == 'Action':
                        actionValue = policyStatement[values]
                        if type(actionValue) == str:
                            if actionValue == "*":
                                return CheckResult.FAILED
                            else:
                                return CheckResult.PASSED
                        elif type(actionValue) == list:
                            resourceHasWildcardValue = 'false'
                            for index1,values1 in enumerate(actionValue):
                                splitString = values1.split(':')
                                for index2,value2 in enumerate(splitString):
                                    if value2 == '*':
                                        resourceHasWildcardValue = 'true'
                            if resourceHasWildcardValue == 'true':
                                return CheckResult.FAILED
                            else:
                                return CheckResult.PASSED

            else:
                return None
        else:
            return None

scanner = IAMPolicyActionCustomizedCheck()