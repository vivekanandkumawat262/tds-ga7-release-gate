from fastapi import FastAPI
from typing import Any
import re

app = FastAPI()


# Your assigned scope
ASSIGNED_TENANT = "tenant-mkc2fyf"
ALLOWED_EMAIL_DOMAIN = "notify-v6i11cb.example"


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):
    violations = []

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # --------------------------------------------------
    # 1. Permissions must be EXACTLY least privilege
    # --------------------------------------------------
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    permissions = workflow.get("permissions", {})

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # --------------------------------------------------
    # 2. Pull request must use pull_request
    # --------------------------------------------------
    event = payload.get("event")
    trigger = workflow.get("trigger")

    if event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # --------------------------------------------------
    # 3. Tests must pass, matrix complete,
    #    failFast must be false
    # --------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # --------------------------------------------------
    # 4. Action pinning
    # --------------------------------------------------
    actions = workflow.get("actions", [])

    for action in actions:
        owner = action.get("owner")
        ref = action.get("ref", "")

        # Official actions/* may use tags
        if owner == "actions":
            continue

        # Third-party actions require exactly
        # 40 lowercase hexadecimal characters
        if (
            len(ref) != 40
            or any(c not in "0123456789abcdef" for c in ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # --------------------------------------------------
    # 5. Image must be multi-stage
    # --------------------------------------------------
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # --------------------------------------------------
    # 6. Container must not run as root
    # --------------------------------------------------
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # --------------------------------------------------
    # 7. Secret handling
    # --------------------------------------------------
    secret_mode = image.get("secretMode")

    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # --------------------------------------------------
    # 8. Critical vulnerabilities must be zero
    # --------------------------------------------------
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # --------------------------------------------------
    # 9. Image must be digest pinned
    # --------------------------------------------------
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # --------------------------------------------------
    # 10. Production requirements
    # --------------------------------------------------
    if payload.get("target") == "production":

        if (
            event != "push"
            or payload.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # --------------------------------------------------
    # Final decision
    # --------------------------------------------------
    decision = "promote" if not violations else "block"

    return {
        "decision": decision,
        "violations": violations,
    }




# ============================================================
# Question 2: /action-firewall
# ============================================================

def valid_string(value):
    return isinstance(value, str)


def exact_keys(obj, required_keys):
    return (
        isinstance(obj, dict)
        and set(obj.keys()) == set(required_keys)
    )


def valid_top_level(payload):
    if not isinstance(payload, dict):
        return False

    allowed_keys = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action",
    }

    # untrustedContent is optional
    if set(payload.keys()) - allowed_keys:
        return False

    required = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required.issubset(payload.keys()):
        return False

    if payload["provenance"] not in ("trusted", "untrusted"):
        return False

    if not isinstance(payload["humanApproved"], bool):
        return False

    if "untrustedContent" in payload:
        if not isinstance(payload["untrustedContent"], str):
            return False

    action = payload["action"]

    if not isinstance(action, dict):
        return False

    if set(action.keys()) != {"tool", "args"}:
        return False

    if not isinstance(action["tool"], str):
        return False

    if not isinstance(action["args"], dict):
        return False

    return True


def valid_search_args(args):
    if not exact_keys(args, {"query"}):
        return False

    query = args["query"]

    if not isinstance(query, str):
        return False

    if not (1 <= len(query) <= 200):
        return False

    return True


def valid_lookup_args(args):
    if not exact_keys(args, {"tenantId", "recordId"}):
        return False

    if not isinstance(args["tenantId"], str):
        return False

    if not isinstance(args["recordId"], str):
        return False

    if args["recordId"] == "":
        return False

    return True


def valid_email_args(args):
    if not exact_keys(args, {"to", "subject", "body"}):
        return False

    if not isinstance(args["to"], str):
        return False

    if not isinstance(args["subject"], str):
        return False

    if not isinstance(args["body"], str):
        return False

    return True


def valid_html_args(args):
    if not exact_keys(args, {"html"}):
        return False

    if not isinstance(args["html"], str):
        return False

    return True


def unsafe_html(html):
    # Block script elements
    if re.search(r"<\s*script\b", html, re.IGNORECASE):
        return True

    # Block iframe elements
    if re.search(r"<\s*iframe\b", html, re.IGNORECASE):
        return True

    # Block inline event handlers such as:
    # onclick=, onload=, onerror=, onmouseover=, etc.
    if re.search(r"\bon[a-zA-Z]+\s*=", html, re.IGNORECASE):
        return True

    # Block javascript: URLs
    if re.search(r"javascript\s*:", html, re.IGNORECASE):
        return True

    return False


@app.post("/action-firewall")
def action_firewall(payload: dict[str, Any]):

    # --------------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # --------------------------------------------------------
    if not valid_top_level(payload):
        return {
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        }

    action = payload["action"]
    tool = action["tool"]
    args = action["args"]

    # --------------------------------------------------------
    # 2. TOOL ALLOWLIST
    # --------------------------------------------------------
    allowed_tools = {
        "search",
        "lookup_record",
        "send_email",
        "render_html",
    }

    if tool not in allowed_tools:
        return {
            "decision": "block",
            "reason": "TOOL_NOT_ALLOWED"
        }

    # --------------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMA
    # --------------------------------------------------------
    if tool == "search":
        if not valid_search_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "lookup_record":
        if not valid_lookup_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "send_email":
        if not valid_email_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    elif tool == "render_html":
        if not valid_html_args(args):
            return {
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            }

    # --------------------------------------------------------
    # 4. TENANT SCOPE
    # --------------------------------------------------------
    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return {
                "decision": "block",
                "reason": "TENANT_SCOPE"
            }

    # --------------------------------------------------------
    # 5. EXACT EMAIL DOMAIN
    # --------------------------------------------------------
    if tool == "send_email":

        recipient = args["to"]

        # Exactly one @
        if recipient.count("@") != 1:
            return {
                "decision": "block",
                "reason": "EGRESS_DENIED"
            }

        local_part, domain = recipient.rsplit("@", 1)

        if not local_part or domain != ALLOWED_EMAIL_DOMAIN:
            return {
                "decision": "block",
                "reason": "EGRESS_DENIED"
            }

    # --------------------------------------------------------
    # 6. HUMAN APPROVAL
    # --------------------------------------------------------
    if tool == "send_email":
        if payload["humanApproved"] is not True:
            return {
                "decision": "block",
                "reason": "APPROVAL_REQUIRED"
            }

    # --------------------------------------------------------
    # 7. HTML SAFETY
    # --------------------------------------------------------
    if tool == "render_html":
        if unsafe_html(args["html"]):
            return {
                "decision": "block",
                "reason": "UNSAFE_OUTPUT"
            }

    # --------------------------------------------------------
    # ALLOW
    # --------------------------------------------------------
    return {
        "decision": "allow",
        "reason": "ALLOW"
    }