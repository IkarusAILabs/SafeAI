# BENCH verdict-unknown: interpolated values shadow the conclusion.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}
resource "aws_iam_role_policy" "inline" {
  name = "inline"
  role = aws_iam_role.agent_role.name
  statement {
    actions   = ["s3:${var.extra}"]
    resources = ["*"]
  }
}
