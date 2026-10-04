# Role name and policy content arrive via variables: unresolvable statically.
resource "aws_iam_role" "agent_role" {
  name = var.role_name
}

resource "aws_iam_role_policy" "agent_policy" {
  name   = "agent-policy"
  role   = aws_iam_role.agent_role.name
  policy = var.policy_json
}
