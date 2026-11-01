resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}

resource "aws_iam_role_policy" "agent_inline" {
  name = "agent-inline"
  role = aws_iam_role.agent_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "cloudtrail:StopLogging"]
      Resource = ["*"]
    }]
  })
}

resource "aws_iam_role" "auditor_role" {
  name = "auditor-role"
}

resource "aws_iam_role_policy" "auditor_inline" {
  name = "auditor-inline"
  role = aws_iam_role.auditor_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["cloudtrail:LookupEvents", "s3:GetObject"]
      Resource = ["*"]
    }]
  })
}
