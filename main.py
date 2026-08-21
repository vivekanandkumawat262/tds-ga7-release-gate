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



# ============================================================
# Question 3: /terraform/plan
# ============================================================

TERRAFORM_WORKSPACE = "prod-qpc0oo"

REQUIRED_LABELS = {
    "owner": "student-oszqt",
    "environment": "production",
    "cost_center": "cc-7jnf",
}


def exact_type(value, expected_type):
    """
    Strict type check.
    This prevents True from being accepted as an integer, etc.
    """
    return type(value) is expected_type


def valid_terraform_schema(payload):
    """
    Validate the required fields and their types.
    Extra fields are allowed because the question specifies
    value-type validation rather than an exact-key schema.
    """

    if type(payload) is not dict:
        return False

    # Required top-level fields
    required = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required.issubset(payload.keys()):
        return False

    # environment
    if type(payload["environment"]) is not str:
        return False

    # state
    state = payload["state"]

    if type(state) is not dict:
        return False

    if "backend" not in state or "locked" not in state:
        return False

    if type(state["backend"]) is not str:
        return False

    if type(state["locked"]) is not bool:
        return False

    # providerVersion
    if type(payload["providerVersion"]) is not str:
        return False

    # destroyApproved
    if type(payload["destroyApproved"]) is not bool:
        return False

    # resource
    resource = payload["resource"]

    if type(resource) is not dict:
        return False

    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not required_resource.issubset(resource.keys()):
        return False

    if type(resource["address"]) is not str:
        return False

    if type(resource["type"]) is not str:
        return False

    if type(resource["action"]) is not str:
        return False

    if type(resource["labels"]) is not dict:
        return False

    for key, value in resource["labels"].items():
        if type(key) is not str:
            return False

        if type(value) is not str:
            return False

    # secret: null OR string
    if resource["secret"] is not None:
        if type(resource["secret"]) is not str:
            return False

    # forceDestroy must be boolean
    if type(resource["forceDestroy"]) is not bool:
        return False

    return True

def valid_secret_reference(secret):
    """
    secret must be:
      null
      OR
      non-empty secret://... reference
    """

    if secret is None:
        return True

    if not isinstance(secret, str):
        return False

    if not secret.startswith("secret://"):
        return False

    # Must contain something after secret://
    if len(secret) <= len("secret://"):
        return False

    return True


@app.post("/terraform/plan")
def terraform_plan(payload: dict[str, Any]):

    # --------------------------------------------------------
    # 1. INVALID PLAN
    # --------------------------------------------------------
    if not valid_terraform_schema(payload):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }

    resource = payload["resource"]
    state = payload["state"]

    # --------------------------------------------------------
    # 2. ENVIRONMENT
    # --------------------------------------------------------
    if payload["environment"] != TERRAFORM_WORKSPACE:
        return {
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH"
        }

    # --------------------------------------------------------
    # 3. STATE SAFETY
    # --------------------------------------------------------
    allowed_backends = {
        "gcs",
        "s3",
        "azurerm",
        "remote",
    }

    if (
        state["backend"] not in allowed_backends
        or state["locked"] is not True
    ):
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE"
        }

    # --------------------------------------------------------
    # 4. PROVIDER PINNING
    # --------------------------------------------------------
    provider = payload["providerVersion"]

    allowed_provider_versions = {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }

    if provider not in allowed_provider_versions:
        return {
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER"
        }

    # --------------------------------------------------------
    # 5. REQUIRED LABELS
    # --------------------------------------------------------
    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():

        if key not in labels:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS"
            }

        if labels[key] != expected_value:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS"
            }

    # --------------------------------------------------------
    # 6. SECRET
    # --------------------------------------------------------
    if not valid_secret_reference(resource["secret"]):
        return {
            "decision": "reject",
            "reason": "PLAINTEXT_SECRET"
        }

    # --------------------------------------------------------
    # 7. DESTRUCTIVE DELETE
    # --------------------------------------------------------
    stateful_resources = {
        "storage_bucket",
        "sql_database",
        "persistent_disk",
    }

    if (
        resource["action"] == "delete"
        and resource["type"] in stateful_resources
        and payload["destroyApproved"] is not True
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED"
        }

    # --------------------------------------------------------
    # 8. FORCE DESTROY
    # --------------------------------------------------------
    if (
        resource["type"] == "storage_bucket"
        and payload["environment"] == TERRAFORM_WORKSPACE
        and resource["forceDestroy"] is True
    ):
        return {
            "decision": "reject",
            "reason": "FORCE_DESTROY"
        }

    # --------------------------------------------------------
    # EVERYTHING PASSED
    # --------------------------------------------------------
    return {
        "decision": "approve",
        "reason": "APPROVE"
    }