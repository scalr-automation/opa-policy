variable "v" {
  type    = string
  default = "ok"
}

resource "terraform_data" "e" {
  input = var.v
}
