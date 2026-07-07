package common

# Reusable helper shared across policy groups via the "common functions folder".
# Returns true when the given value is present in the allow-list.
is_allowed(value) {
	allowed := {"success", "passed", "auto-test"}
	allowed[value]
}
