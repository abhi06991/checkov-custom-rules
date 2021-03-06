from typing import Dict, List, Any

from checkov.common.util.type_forcers import force_list
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class AdminPolicyResource(BaseResourceCheck):
    def __init__(self) -> None:
        name = 'Ensure IAM policies that allow full "*-*" administrative privileges are not created'
        id = "CKV_AWS_GS_1"
        supported_resources = ["aws_iam_policy"]
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: Dict[str, List[Any]]) -> CheckResult:
        """
            validates iam policy document
            https://learn.hashicorp.com/terraform/aws/iam-policy
        :param conf: aws_kms_key configuration
        :return: <CheckResult>
        """

        for statement in conf.get("statement", []):
            if not isinstance(statement, list):
                statement = [statement]
            for stmt in statement:
                if (
                    isinstance(stmt, dict)
                    and stmt.get("effect", ["Allow"]) == ["Allow"]
                    and stmt.get("actions")
                    and "*" in force_list(stmt["actions"][0])
                    and stmt.get("resources")
                    and "*" in force_list(stmt["resources"][0])
                ):
                    return CheckResult.FAILED

        return CheckResult.PASSED


check = AdminPolicyResource()