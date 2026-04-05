package terraform

# Block apply when PR/MR is not mergeable (GitHub)
deny[msg] {
    input.tfrun.is_destroy == false
    input.tfrun.is_dry == false
    input.tfrun.source == "comment-github"
    input.tfrun.vcs.pull_request != null
    input.tfrun.vcs.pull_request.merged_by == null
    input.tfrun.vcs.pull_request.merge_error != null
    msg := sprintf("Apply is not allowed: PR is not mergeable (%s)", [input.tfrun.vcs.pull_request.merge_error])
}

# Block apply when PR/MR is not mergeable (GitLab)
deny[msg] {
    input.tfrun.is_destroy == false
    input.tfrun.is_dry == false
    input.tfrun.source == "comment-gitlab"
    input.tfrun.vcs.pull_request != null
    input.tfrun.vcs.pull_request.merged_by == null
    input.tfrun.vcs.pull_request.merge_error != null
    msg := sprintf("Apply is not allowed: MR is not mergeable (%s)", [input.tfrun.vcs.pull_request.merge_error])
}
