# BENCH dynamic-for-each: generated statements stay unresolved.
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_policy" "dyn" {
  name = "dyn"
  dynamic "statement" {
    for_each = var.statements
    content {
      actions   = statement.value.actions
      resources = ["*"]
    }
  }
}
