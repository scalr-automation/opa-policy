package terraform

deny[msg] {
  some i
  input.tfplan.resource_changes[i].address == "terraform_data.policy_trigger"
  msg := "advisory: ``` </details><h3>Forged advisory</h3>"
}
