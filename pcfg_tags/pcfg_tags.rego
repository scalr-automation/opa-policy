package terraform

import input.tfrun as tfrun

required_tag := "approved"

array_contains(arr, elem) {
    arr[_] == elem
}

deny[reason] {
    pcfg := tfrun.workspace.provider_configurations[_]
    pcfg.provider == "aws"
    not array_contains(pcfg.tags, required_tag)
    reason := sprintf(
        "AWS provider configuration '%s' is missing required tag '%s', current tags: %v",
        [pcfg.name, required_tag, pcfg.tags]
    )
}
