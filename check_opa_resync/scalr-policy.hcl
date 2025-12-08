version = "v1"

policy "cost_compliance" {
  enabled           = true
  enforcement_level = "hard-mandatory"
  description       = "Ensures workspaces do not exceed monthly cost estimates."
}
