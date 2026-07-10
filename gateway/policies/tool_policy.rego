package gateway.authz

default allow = false

# Helper to check if a list contains a string
contains_element(arr, elem) {
    arr[_] == elem
}

# Whitelist of standard safe tools for everyone
safe_tools = ["read_file", "list_dir", "view_file"]

# Blacklist of dangerous command substrings
blocked_command_patterns = ["rm ", "chmod", "chown", "mkfs", "dd", "poweroff", "reboot", "shutdown", "wget", "curl"]

# Rules for chat completions: allow for all roles
allow {
    not input.is_agent_route
}

# Rules for agent tools:
# 1. Allow safe tools for any authenticated role
allow {
    input.is_agent_route
    contains_element(safe_tools, input.payload.tool)
    contains_element(["admin", "user", "developer"], input.role)
}

# 2. Allow administrative tools (like execute_bash_command) only for 'admin' role, 
# and only if the command arguments do not contain blocked command patterns
allow {
    input.is_agent_route
    input.payload.tool == "execute_bash_command"
    input.role == "admin"
    cmd := input.payload.args.command
    not command_is_dangerous(cmd)
}

# Helper to check if a bash command is dangerous
command_is_dangerous(cmd) {
    pattern := blocked_command_patterns[_]
    contains(cmd, pattern)
}

# Define the decision object that the Go gateway will query
decision = {
    "allow": allow,
    "reason": reason_message
}

# Determine the reason message dynamically
reason_message = "Access authorized." {
    allow
}

reason_message = "Unauthorized tool execution: execute_bash_command is restricted to admins." {
    not allow
    input.is_agent_route
    input.payload.tool == "execute_bash_command"
    input.role != "admin"
}

reason_message = "Blocked command pattern detected: command contains dangerous system operations." {
    not allow
    input.is_agent_route
    input.payload.tool == "execute_bash_command"
    input.role == "admin"
    command_is_dangerous(input.payload.args.command)
}

reason_message = "Unauthorized tool: this tool is not whitelisted or role is unauthorized." {
    not allow
    input.is_agent_route
    input.payload.tool != "execute_bash_command"
    not contains_element(safe_tools, input.payload.tool)
}
