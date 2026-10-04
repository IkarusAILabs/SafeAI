# Policy actions expand from a variable: dynamic content, unknown statically.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}

resource "aws_iam_role_policy" "agent_policy" {
  name = "agent-policy"
  role = aws_iam_role.agent_role.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = var.allow_actions
      Resource = "*"
    }]
  })
}
