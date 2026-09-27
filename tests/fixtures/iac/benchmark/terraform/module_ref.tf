# BENCH module-ref: modules are recorded, never expanded.
module "iam" {
  source = "./modules/iam"
  role   = "app-role"
}
resource "aws_iam_role" "app" {
  name = "app-role"
}
