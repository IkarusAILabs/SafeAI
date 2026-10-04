# Role with no policy of its own: grants nothing by itself.
resource "aws_iam_role" "idle_role" {
  name = "idle-role"
}
