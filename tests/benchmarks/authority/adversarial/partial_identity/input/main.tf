# Partial identity reference: matches agent-role AND agent-role-prod
# by prefix, so it must not establish any identity link.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}

resource "aws_iam_role" "agent_role_prod" {
  name = "agent-role-prod"
}
