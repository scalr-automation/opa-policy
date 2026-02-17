package terraform

import input.tfrun as tfrun

required_tag := "approved"

# Default to empty list if tags key is missing or null
tags_list(pcfg) := xs if {
    xs := pcfg.tags
}
tags_list(pcfg) := [] if {
    not pcfg.tags
}

array_contains(arr, elem) if {
    arr[_] == elem
}

# Fail when workspace has no provider configurations (nothing to iterate → policy would pass)
deny contains reason if {
    count(tfrun.workspace.provider_configurations) == 0
    reason := "No provider configurations in workspace; policy requires at least one AWS provider configuration to validate tags."
}

# Fail when any AWS provider config is missing the required tag (covers no tags / wrong tags)
deny contains reason if {
    pcfg := tfrun.workspace.provider_configurations[_]
    pcfg.provider == "aws"
    tags := tags_list(pcfg)
    not array_contains(tags, required_tag)
    reason := sprintf(
        "AWS provider configuration '%s' is missing required tag '%s'; current tags: %v",
        [pcfg.name, required_tag, tags]
    )
}
