# Two roles; config binds each agent entrypoint to its own role.
resource "aws_iam_role" "role_a" {
  name = "role-a"
}

resource "aws_iam_role_policy" "role_a_read" {
  name = "role-a-read"
  role = aws_iam_role.role_a.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::agent-bucket/*"]
    }]
  })
}

resource "aws_iam_role" "role_b" {
  name = "role-b"
}

resource "aws_iam_role_policy" "role_b_admin" {
  name = "role-b-admin"
  role = aws_iam_role.role_b.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = ["*"]
    }]
  })
}
