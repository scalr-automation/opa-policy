package terraform

deny[msg] {
  input.tfrun.is_dry
  input.tfrun.workspace.name == "qa41350-tf"
  msg := "pre-advisory: ``` </details><h3>Forged pre-plan advisory</h3>"
}
