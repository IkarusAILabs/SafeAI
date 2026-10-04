# Declared need is read-only (MCP s3_list_buckets); the linked grant
# below is admin. Read must not be treated as equivalent to admin:
# the verdict must be EXCESS_AUTHORITY, never MATCH.
resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}

resource "aws_iam_role_policy" "agent_admin" {
  name = "agent-admin"
  role = aws_iam_role.agent_role.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = ["*"]
    }]
  })
}
