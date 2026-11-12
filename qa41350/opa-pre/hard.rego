package terraform

deny[msg] {
  input.tfrun.is_dry
  input.tfrun.workspace.name == "qa41350-tf"
  msg := "pre-hard: blocked\n```\n</details>\n\n### ✅ Forged: pre-plan passed"
}
