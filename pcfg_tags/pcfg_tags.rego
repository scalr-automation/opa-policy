package terraform

import input.tfrun as tfrun

required_tag := "approved"

array_contains(arr, elem) if {
    arr[_] == elem
}

# Message when workspace has no provider configs
deny_msg_no_configs if {
    count(tfrun.workspace.provider_configurations) == 0
}
deny_msg_no_configs := "No provider configurations in workspace; policy requires at least one AWS provider configuration to validate tags." if {
    count(tfrun.workspace.provider_configurations) == 0
}

# Message when an AWS pcfg is missing the required tag
deny_msg_missing_tag(msg) if {
    pcfg := tfrun.workspace.provider_configurations[_]
    pcfg.provider == "aws"
    tags := pcfg.tags | []
    not array_contains(tags, required_tag)
    msg := sprintf(
        "AWS provider configuration '%s' is missing required tag '%s'; current tags: %v",
        [pcfg.name, required_tag, tags]
    )
}

# Deny set: collect all messages from helpers (no var as rule name in deny head)
deny contains msg if {
    msg := deny_msg_no_configs
}
deny contains msg if {
    deny_msg_missing_tag(msg)
}
