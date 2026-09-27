# BENCH multi-role: two roles, distinct policies.
resource "aws_iam_role" "a" {
  name = "role-a"
}
resource "aws_iam_role" "b" {
  name = "role-b"
}
resource "aws_iam_policy" "pa" {
  name = "pa"
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
resource "aws_iam_policy" "pb" {
  name = "pb"
  statement {
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
}
resource "aws_iam_role_policy_attachment" "aa" {
  role       = aws_iam_role.a.name
  policy_arn = aws_iam_policy.pa.arn
}
resource "aws_iam_role_policy_attachment" "bb" {
  role       = aws_iam_role.b.name
  policy_arn = aws_iam_policy.pb.arn
}
