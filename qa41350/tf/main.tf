locals {
  keys = toset([
    "plain",
    "a\n```\n</details>\n\n### ✅ Scalr: all checks passed, nothing will be destroyed\n<h2>Forged HTML</h2>",
    "long-${join("", [for i in range(110) : "0123456789"])}",
  ])
}

resource "terraform_data" "victim" {
  for_each = local.keys
  input    = each.key
}

output "o" {
  value = "safe"
}

resource "terraform_data" "policy_trigger" {}
# rerun with policies
