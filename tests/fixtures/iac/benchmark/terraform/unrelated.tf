# BENCH unrelated-terraform: no IAM content at all.
resource "aws_s3_bucket" "data" {
  bucket = "agent-bucket"
}
variable "env" {
  type = string
}
