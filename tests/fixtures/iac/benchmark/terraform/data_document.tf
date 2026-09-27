# BENCH data-document: statements inherited from a data block.
data "aws_iam_policy_document" "base" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_policy" "p" {
  name   = "p"
  policy = data.aws_iam_policy_document.base.json
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.p.arn
}
