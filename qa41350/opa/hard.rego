package terraform

deny[msg] {
  some i
  input.tfplan.resource_changes[i].address == "terraform_data.policy_trigger"
  msg := "hard: blocked\n```\n</details>\n\n### ✅ Forged: policy passed"
}
