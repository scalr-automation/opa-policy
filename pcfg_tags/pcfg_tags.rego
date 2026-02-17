package terraform

import input.tfrun as tfrun

required_tag := "approved"

array_contains(arr, elem) {
    arr[_] == elem
}

# Fail when workspace has no provider configurations
deny[reason] {
    count(tfrun.workspace.provider_configurations) == 0
    reason := "No provider configurations in workspace; policy requires at least one AWS provider configuration to validate tags."
}

# Fail when any AWS provider config is missing the required tag
deny[reason] {
    pcfg := tfrun.workspace.provider_configurations[_]
    pcfg.provider == "aws"
    tags := pcfg.tags | []
    not array_contains(tags, required_tag)
    reason := sprintf(
        "AWS provider configuration '%s' is missing required tag '%s'; current tags: %v",
        [pcfg.name, required_tag, tags]
    )
}
