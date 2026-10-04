# Least-privilege role for the read-only support agent.
resource "aws_iam_role" "support_role" {
  name = "support-role"
}

resource "aws_iam_role_policy" "support_read" {
  name = "support-read"
  role = aws_iam_role.support_role.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::support-docs/*"]
    }]
  })
}
