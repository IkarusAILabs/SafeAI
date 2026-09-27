# BENCH wildcard-admin: full star grant (observed breadth, flagged).
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_role_policy" "inline" {
  name = "inline"
  role = aws_iam_role.app.name
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
