from lark import Token
import pprint
from checkov.terraform.checks.module.base_module_check import BaseModuleCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class moduleCheck(BaseModuleCheck):
    def __init__(self):
        name = "Resource defines outdated SSL/TLS policies(missing viewer_certificate block)"
        id = "CKV_GS_AWS_100047"
        supported_resources = ['aws_cloudfront_distribution']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories)

    def scan_module_conf(self, conf):
        pprint.pprint(conf)
        pprint.pprint(self)



blockScanner = moduleCheck()