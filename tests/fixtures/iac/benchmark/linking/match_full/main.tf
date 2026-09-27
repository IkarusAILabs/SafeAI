# BENCH verdict-match: linked role with a covering grant.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}
resource "aws_iam_policy" "p" {
  name = "p"
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.agent_role.name
  policy_arn = aws_iam_policy.p.arn
}
