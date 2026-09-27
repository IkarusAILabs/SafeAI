# BENCH malformed: unbalanced brace tail is skipped, never guessed.
resource "aws_iam_policy" "broken" {
  statement {
    actions = ["s3:*"]
