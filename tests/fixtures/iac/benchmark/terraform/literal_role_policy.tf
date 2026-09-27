# BENCH literal-role-policy: role + inline policy, all literal.
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_role_policy" "inline" {
  name = "inline"
  role = aws_iam_role.app.name
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::b/*"]
  }
}
