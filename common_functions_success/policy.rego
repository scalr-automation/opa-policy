package terraform

import data.common

# This rule can only be evaluated if the shared "common" functions were imported
# from the common functions folder before evaluation. "success" is in the
# allow-list, so common.is_allowed returns true and the policy passes (deny is empty).
deny[msg] {
	not common.is_allowed("success")
	msg := "value rejected by common function common.is_allowed"
}
