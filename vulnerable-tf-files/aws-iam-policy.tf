resource "aws_iam_policy" "policy" {
  name        = "IAM Resource Policy"
  path        = "/"
  description = "Applies to IAM Resources"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
          "s3:df:d:asdad:asd:asd:*",
          "lambda:as*",
          "logs:dsd",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}
