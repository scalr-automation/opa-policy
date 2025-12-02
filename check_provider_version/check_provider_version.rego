package terraform
import input.tfplan

deny[msg] {
    provider_config := tfplan.configuration.provider_config["aws"]
    version := provider_config.version_constraint
    semver.compare(version, "5.0.0") == -1
    msg := sprintf("AWS provider version %s is below required 5.0.0", [version])
}
