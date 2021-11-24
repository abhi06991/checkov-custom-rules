import pprint
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class KMSDefaultPolicyCheck(BaseResourceCheck):
    def __init__(self):
        name = "Either no policy defined or default KMS key Policy is used."
        id = "CKV_AWS_GS_4090"
        supported_resources = ['aws_kms_key']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        actionWildcardCheck = "false"
        kmsActionCheck = "false"
        resourceWildcardCheck = "false"
        kmsResourceCheck = "false"
        if 'policy' in conf.keys():
            policyDefined = conf['policy'][0]
            if policyDefined:
                pprint.pprint(policyDefined)
                exit()
                if 'Statement' in conf['policy'][0]:
                    policyStatement = conf['policy'][0]['Statement'][0]
                    for index,values in enumerate(policyStatement):
                        if values == "Action":
                            actionValue = policyStatement[values]
                            if type(actionValue) == str:
                                if actionValue == "*":
                                    actionWildcardCheck = "true"
                                splitString = actionValue.split(':')
                                if "s3" in splitString:
                                    for index2,value2 in enumerate(splitString):
                                        if value2 == "*":
                                            s3ActionCheck = "true"
                                        elif value2 == "GetObject":
                                            s3ActionCheck = "true"

                            elif type(actionValue) == list:
                                for index1,values1 in enumerate(actionValue):
                                    if values1 == "*":
                                        actionWildcardCheck = "true"
                                    splitString = values1.split(':')
                                    if "s3" in splitString:
                                        if"GetObject" in values1:
                                            s3ActionCheck = "true"
                                        else:
                                            for index2,value2 in enumerate(splitString):
                                                if value2 == "*":
                                                    s3ActionCheck = "true"
                        if values == "Resource":
                            resourceValue = policyStatement[values]
                            if type(resourceValue) == str:
                                if resourceValue == "*":
                                    resourceWildcardCheck = "true"
                                splitString = resourceValue.split(':')
                                if "s3" in splitString:
                                    for index2,value2 in enumerate(splitString):
                                        if value2 == "*":
                                            s3ResourceCheck = "true"
                            elif type(resourceValue) == list:
                                for index1,values1 in enumerate(resourceValue):
                                    if values1 == "*":
                                        resourceWildcardCheck = "true"
                                    splitString = values1.split(':')
                                    if "s3" in splitString:
                                        for index2,value2 in enumerate(splitString):
                                            if value2 == "*":
                                                s3ResourceCheck = "true"
                    if (actionWildcardCheck == "true" or s3ActionCheck == "true") and (resourceWildcardCheck == "true" or s3ResourceCheck == "true"):
                        return CheckResult.FAILED
                    else:
                        return CheckResult.PASSED
                else:
                    return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        else:
            return CheckResult.FAILED
scanner = KMSDefaultPolicyCheck()
