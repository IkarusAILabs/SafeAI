# Baseline identity: agent-role with read access.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
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
