# Managed AWS policy attached by ARN: content lives outside the repo.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}

resource "aws_iam_role_policy_attachment" "managed" {
  role       = aws_iam_role.agent_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}
