# Agent role with a wildcard grant plus an attached policy whose
# actions mix literal and interpolated values (partially resolved).
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}

resource "aws_iam_policy" "broad" {
  name = "broad"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = ["*"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "broad_attach" {
  role       = aws_iam_role.agent_role.name
  policy_arn = aws_iam_policy.broad.arn
}

resource "aws_iam_policy" "mixed" {
  name = "mixed"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:ListBucket", "s3:${var.extra}"]
      Resource = ["arn:aws:s3:::${var.bucket}/*"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "mixed_attach" {
  role       = aws_iam_role.agent_role.name
  policy_arn = aws_iam_policy.mixed.arn
}
