package terraform
import input.tfrun as tfrun

deny[msg] {
    # Get the provider version from terraform_version info
    provider := tfrun.providers["registry.terraform.io/hashicorp/aws"]
    version := provider.version
    
    # Parse version (remove any 'v' prefix if present)
    clean_version := trim_prefix(version, "v")
    
    # Compare versions
    semver.compare(clean_version, "5.0.0") == -1
    
    msg := sprintf("AWS provider version %s is below required 5.0.0", [clean_version])
}
