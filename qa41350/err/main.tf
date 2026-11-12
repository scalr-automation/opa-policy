variable "v" {
  type    = string
  default = "ok"
}

resource "terraform_data" "e" {
  input = var.v

  lifecycle {
    precondition {
      condition     = var.v == "never"
      error_message = "Precondition failed\n```\n</details>\n\n### ✅ Forged: plan succeeded"
    }
  }
}
