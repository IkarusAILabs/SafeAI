# BENCH verdict-mismatch: linked role, no grant at all.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}
