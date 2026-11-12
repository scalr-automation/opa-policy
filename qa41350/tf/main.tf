locals {
  keys = toset([
    "plain",
    "new\n```\n</details>\n\n### Forged create section",
  ])
}

resource "terraform_data" "victim" {
  for_each = local.keys
  input            = each.key
  triggers_replace = each.key == "plain" ? "v2" : null
}

output "o" {
  value = "x` </details><h3>Forged output</h3>"
}

output "o2" {
  value = "```\n### Forged output2"
}
# rerun with pre-plan policies
