package terraform

import input.tfplan

deny[msg] {
    provider_config := tfplan.configuration.provider_config.aws
    version := provider_config.version_constraint
    major := to_number(split(version, ".")[0])
    major < 5
    msg := sprintf("AWS provider version %s is below required 5.0.0", [version])
}
