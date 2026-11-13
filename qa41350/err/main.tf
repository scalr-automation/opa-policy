variable "v" {
  type    = string
  default = "ok"
}

resource "terraform_data" "e" {
  input = var.v
}

resource "terraform_data" "normal" {
  for_each = toset(["alpha", "beta"])
  input    = each.key
}

output "plain" {
  value = "hello"
}

output "secret" {
  value     = "s3cr3t"
  sensitive = true
}

output "listy" {
  value = ["a", "b"]
}
