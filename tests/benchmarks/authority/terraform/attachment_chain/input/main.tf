# Agent role with a managed policy attached by reference.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}

resource "aws_iam_policy" "agent_write" {
  name = "agent-write"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = ["arn:aws:s3:::agent-bucket/*"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "agent_attach" {
  role       = aws_iam_role.agent_role.name
  policy_arn = aws_iam_policy.agent_write.arn
}
