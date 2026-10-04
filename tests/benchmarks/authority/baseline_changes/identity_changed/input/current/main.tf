# Current identity: deployer-role replaces agent-role (broader scope).
resource "aws_iam_role" "deployer_role" {
  name = "deployer-role"
}

resource "aws_iam_role_policy" "deployer_full" {
  name = "deployer-full"
  role = aws_iam_role.deployer_role.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = ["*"]
    }]
  })
}
