resource "aws_iam_role" "admin_role" {
  name = "admin-role"
}

resource "aws_iam_role_policy" "admin_inline" {
  name = "admin-inline"
  role = aws_iam_role.admin_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = ["*"]
    }]
  })
}
