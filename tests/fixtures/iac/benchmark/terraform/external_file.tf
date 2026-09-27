# BENCH external-file: policy body lives outside the repo scan.
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_role_policy" "inline" {
  name   = "inline"
  role   = aws_iam_role.app.name
  policy = file("policy.json")
}
