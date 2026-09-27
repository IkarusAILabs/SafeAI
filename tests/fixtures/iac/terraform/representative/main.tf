# Representative Terraform IAM sample for SafeAI v2.5 IaC evidence.
# Expected records (ground truth for the benchmark corpus):
#  identities: aws_iam_role agent-role @ main.tf
#  grants: identity (role agent-role), actions [s3:GetObject,
#    s3:PutObject] (resolved), resources [arn:aws:s3:::agent-bucket/*]
#    (resolved, wildcard-pattern) @ main.tf (policy agent-s3-access)
#  grant_bindings: role agent-role -> attachment attach ->
#    policy agent-s3-access @ main.tf
#  verdicts (with declared s3 capability, no link): UNVERIFIED_LINK

resource "aws_iam_role" "agent_role" {
  name = "agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
  })
}

resource "aws_iam_policy" "agent_s3" {
  name = "agent-s3-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = ["arn:aws:s3:::agent-bucket/*"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.agent_role.name
  policy_arn = aws_iam_policy.agent_s3.arn
}
