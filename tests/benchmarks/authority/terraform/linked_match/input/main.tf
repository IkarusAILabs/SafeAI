# Read-only grant matching the declared read need, with an explicit
# identity link: the expected verdict is MATCH.
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
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::agent-bucket", "arn:aws:s3:::agent-bucket/*"]
    }]
  })
}
