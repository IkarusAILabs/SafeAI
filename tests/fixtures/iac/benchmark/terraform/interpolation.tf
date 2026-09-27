# BENCH interpolation: values split literal vs unresolved.
resource "aws_iam_role" "app" {
  name = "app-${var.env}"
}
resource "aws_iam_role_policy" "inline" {
  name = "inline"
  role = aws_iam_role.app.name
  statement {
    actions   = ["s3:ListBucket", "s3:${var.extra}"]
    resources = ["arn:aws:s3:::${var.bucket}/*"]
  }
}
