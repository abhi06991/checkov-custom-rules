from lark import Token
import pprint
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class cloudFrontDistributionBlockCheck(BaseResourceCheck):
    def __init__(self):
        name = "Resource defines outdated SSL/TLS policies(missing viewer_certificate block)"
        id = "CKV_GS_AWS_100047"
        supported_resources = ['aws_cloudfront_distribution']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'viewer_certificate' in conf.keys():
            viewerCertificateBlock = conf['viewer_certificate']
            return CheckResult.PASSED
        else:
            return CheckResult.FAILED


blockScanner = cloudFrontDistributionBlockCheck()


class cloudFrontDistributionProtocolVersionCheck(BaseResourceCheck):
    def __init__(self):
        name = "Resource defines outdated SSL/TLS policies(missing minimum_protocol_version attribute in 'viewer_certificate' block)"
        id = "CKV_GS_AWS_100048"
        supported_resources = ['aws_cloudfront_distribution']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'viewer_certificate' in conf.keys():
            viewerCertificateBlock = conf['viewer_certificate']
            if 'minimum_protocol_version' in viewerCertificateBlock[0]:
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        else:
            return None


versionScanner = cloudFrontDistributionProtocolVersionCheck()


class cloudFrontDistributionProtocolMinVersionCheck(BaseResourceCheck):
    def __init__(self):
        name = "Resource defines outdated SSL/TLS policies(not using 'TLSv1.2_2019')"
        id = "CKV_GS_AWS_100050"
        supported_resources = ['aws_cloudfront_distribution']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'viewer_certificate' in conf.keys():
            viewerCertificateBlock = conf['viewer_certificate']
            if 'minimum_protocol_version' in viewerCertificateBlock[0]:
                version = viewerCertificateBlock[0]['minimum_protocol_version'][0].split('.')[1].split('_')[1]
                if version < '2019':
                    return CheckResult.FAILED
                else:
                    return CheckResult.PASSED
            else:
                return None
        else:
            return None


minVersionScanner = cloudFrontDistributionProtocolMinVersionCheck()