# BENCH verdict-excess: linked wildcard beyond a read need.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}
resource "aws_iam_policy" "wide" {
  name = "wide"
  statement {
    actions   = ["s3:*"]
    resources = ["*"]
  }
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.agent_role.name
  policy_arn = aws_iam_policy.wide.arn
}
