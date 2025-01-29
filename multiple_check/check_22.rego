package terraform

import rego.v1

import input.tfplan as tfplan

deny[reason] if {
    number := to_number(tfplan.variables.check.value)
    required := 1
    number < required

    reason := sprintf("Value of 'check' variable is %d! Required to proceed: %d",[number,required])
}
