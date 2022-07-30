version = "v1"

policy "policy" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "policy1" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}
