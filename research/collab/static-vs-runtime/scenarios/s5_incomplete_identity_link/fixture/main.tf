# Synthetic. A role exists, but no configuration links the agent to it.
resource "aws_iam_role" "reporting" {
  name               = "reporting-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole",
                   Principal = { Service = "ecs-tasks.amazonaws.com" } }]
  })
}
