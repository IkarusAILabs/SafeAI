# BENCH attachment-chain: role -> attachment -> policy -> statement.
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_policy" "p" {
  name = "p"
  statement {
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.p.arn
}
