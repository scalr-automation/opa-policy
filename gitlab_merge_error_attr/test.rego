package terraform

# Block /scalr apply when MR is not mergeable
deny[msg] {
    input.tfrun.is_destroy == false
    input.tfrun.is_dry == false
    input.tfrun.source in ["comment-gitlab", "comment-github"]
    input.tfrun.vcs.pull_request != null
    input.tfrun.vcs.pull_request.merged_by == null
    input.tfrun.vcs.pull_request.merge_error != null
    msg := sprintf("Apply is not allowed: MR is not mergeable (%s)", [input.tfrun.vcs.pull_request.merge_error])
}
