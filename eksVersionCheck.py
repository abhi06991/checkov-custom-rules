from packaging import version
from lark import Token
import pprint
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class EKSVersionCheck(BaseResourceCheck):
    def __init__(self):
        name = "Resource is not using one of the latest three versions of Kubernetes"
        id = "CKV_GS_AWS_1000098"
        supported_resources = ['aws_eks_cluster']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
    	isVersionPreset = 0
    	versionValue = ''
    	if 'version' in conf.keys():
            pprint.pprint(conf['version'][0])
            pprint.pprint('joooo')
            verResult = version.parse("2.3.1") < version.parse("2.3.2")
            pprint.pprint(verResult)
            exit()
    	else:
    		pprint.pprint('bhenn')

    	# pprint.pprint(type(listVal))
    	# pprint.pprint(listVal[0])
    	# for i in listVal:
    	# 	pprint.pprint(type(i))
    	# 	pprint.pprint(listVal[0])
    	# 	exit()
    	# 	if (key == 'version'):
    	# 		isVersionPreset = 1
    	# 		versionValue = val
    	# 		pprint.pprint(versionValue)
    	# 		exit()
    	# if isVersionPreset == 1:
    	# 	return CheckResult.PASSED
    	# else:
    	# 	return None

scanner = EKSVersionCheck()