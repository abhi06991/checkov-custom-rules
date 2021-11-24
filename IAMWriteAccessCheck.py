from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
import pprint

class IAMWriteAccessCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure IAM policies does not allow write access without constraints"
        id = "CKV_AWS_GS_3"
        supported_resources = ['aws_iam_policy']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        s3Actions = ["BypassGovernanceRetention", "DeleteAccessPointPolicy", "DeleteBucketPolicy", "ObjectOwnerOverrideToBucketOwner", "PutAccessPointPolicy", "PutAccountPublicAccessBlock", "PutBucketAcl", "PutBucketPolicy", "PutBucketPublicAccessBlock", "PutObjectAcl", "PutObjectVersionAcl"]
        actionWildcardCheck = "false"
        s3ActionCheck = "false"
        resourceWildcardCheck = "false"
        s3ResourceCheck = "false"   
        if 'policy' in conf.keys():
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
                                    elif value2 in s3Actions:
                                        s3ActionCheck = "true"

                        elif type(actionValue) == list:
                            for index1,values1 in enumerate(actionValue):
                                if values1 == "*":
                                    actionWildcardCheck = "true"
                                splitString = values1.split(':')
                                if "s3" in splitString:
                                    for index2,value2 in enumerate(splitString):
                                        if value2 in s3Actions or value2 == "*":
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
                # if (actionWildcardCheck == "true" and resourceWildcardCheck == "true"):
                #     return CheckResult.FAILED
                # elif (s3ActionCheck == "true" or actionWildcardCheck == "true") and 
                #     return CheckResult.PASSED
            else:
                return None
        else:
            return None

scanner = IAMWriteAccessCheck()