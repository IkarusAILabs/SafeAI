# Two sibling roles. The agent declares read-only S3 use; only the
# read-only attachment below belongs to its role. agent-role-prod must
# never be attributed to this agent by prefix coincidence.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}

resource "aws_iam_role" "agent_role_prod" {
  name = "agent-role-prod"
}

resource "aws_iam_role_policy" "agent_read" {
  name = "agent-read"
  role = aws_iam_role.agent_role.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::agent-bucket/*"]
    }]
  })
}

resource "aws_iam_policy" "prod_admin" {
  name = "prod-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = ["*"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "prod_attach" {
  role       = aws_iam_role.agent_role_prod.name
  policy_arn = aws_iam_policy.prod_admin.arn
}
