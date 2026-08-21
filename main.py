from fastapi import FastAPI, Body
from typing import Any
import re
import html
from urllib.parse import unquote, urlparse

app = FastAPI()


# Your assigned scope
ASSIGNED_TENANT = "tenant-mkc2fyf"
ALLOWED_EMAIL_DOMAIN = "notify-v6i11cb.example"


@app.post("/sanitize-output")
def sanitize_output(payload: Any = Body(...)):
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

    if type(resource["address"]) is not str or resource["address"] == "":
         return False

    if type(resource["type"]) is not str or resource["type"] == "":
        return False

    if type(resource["action"]) is not str:
        return False

    if resource["action"] not in {"create", "update", "delete"}:
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



# ============================================================
# Question 4: /sanitize-output
# ============================================================

ALLOWED_EXTERNAL_HOSTS = {
    "cdn-mkzgavv.example",
    "app-kfmsilv.example",
}

ALLOWED_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


def decode_once(value: str) -> str:
    """
    Decode exactly once in this order:

    1. Percent escapes
    2. HTML entities
    3. \\uXXXX escapes
    """

    # 1. Percent decoding
    decoded = unquote(value)

    # 2. Decode only the HTML entities specified by the question.
    #
    # Numeric:
    #   &#NN;
    #   &#xNN;
    #
    # Named:
    #   &lt; &gt; &quot; &apos; &amp;

    entity_map = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    # Numeric HTML entities
    def decode_numeric_entity(match):
        text = match.group(0)

        try:
            if text.lower().startswith("&#x"):
                number = int(text[3:-1], 16)
            else:
                number = int(text[2:-1], 10)

            return chr(number)
        except (ValueError, OverflowError):
            return text

    decoded = re.sub(
        r"&#(?:[0-9]+|[xX][0-9a-fA-F]+);",
        decode_numeric_entity,
        decoded,
    )

    # Named entities
    for entity, replacement in entity_map.items():
        decoded = decoded.replace(entity, replacement)

    # 3. Decode literal \uXXXX escapes
    def decode_unicode_escape(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        decode_unicode_escape,
        decoded,
    )

    return decoded


def contains_dangerous_scheme(text: str) -> bool:
    """
    Detect:
      javascript:
      data:
      vbscript:

    with optional whitespace before the colon.

    Also detect extracted URLs whose scheme is not
    http/https.
    """

    # Direct dangerous schemes
    if re.search(
        r"(?i)(?:javascript|data|vbscript)\s*:",
        text,
    ):
        return True

    return False


def extract_urls(channel: str, output: str):
    """
    Extract URLs according to the question.
    """

    urls = []

    if channel == "html":

        pattern = re.compile(
            r"""(?i)\b(?:src|href)\s*=\s*(["'])(.*?)\1"""
        )

        for match in pattern.finditer(output):
            urls.append(match.group(2))

    elif channel == "markdown":

        pattern = re.compile(
            r"""\]\(\s*(?:<([^>]+)>|([^)]+))\)"""
        )

        for match in pattern.finditer(output):
            value = match.group(1)

            if value is None:
                value = match.group(2)

            if value is not None:
                urls.append(value.strip())

    elif channel == "url":

        urls.append(output.strip())

    return urls

def safe_urlparse(url: str):
    """
    Parse a URL without allowing malformed input to crash
    the endpoint.
    """
    candidate = url.strip()

    if candidate.startswith("//"):
        candidate = "https:" + candidate

    try:
        return urlparse(candidate)
    except (ValueError, TypeError):
        return None


def url_has_dangerous_scheme(url: str) -> bool:
    """
    Any extracted URL with a scheme other than http/https
    is dangerous.

    Relative URLs have no scheme and are allowed.
    Protocol-relative URLs are treated as https.
    """

    parsed = safe_urlparse(url)

    # Malformed URL: treat it as dangerous rather than
    # allowing the server to crash.
    if parsed is None:
        return True

    if not parsed.scheme:
        return False

    return parsed.scheme.lower() not in {
        "http",
        "https",
    }
def url_is_external_exfil(url: str) -> bool:
    """
    Absolute HTTP/HTTPS URLs must have an exact hostname
    match against the assigned allowlist.

    Relative references are allowed.
    """

    parsed = safe_urlparse(url)

    # Malformed URL
    if parsed is None:
        return True

    # Relative reference such as /local/page
    if not parsed.scheme and not parsed.netloc:
        return False

    # Non-http/https schemes are handled by
    # url_has_dangerous_scheme().
    if parsed.scheme.lower() not in {"http", "https"}:
        return False

    try:
        hostname = parsed.hostname
    except (ValueError, TypeError):
        return True

    if hostname is None:
        return True

    # EXACT hostname comparison
    return hostname.lower() not in ALLOWED_EXTERNAL_HOSTS
def html_has_script_tag(output: str) -> bool:
    """
    Opening script, iframe, object or embed tags.
    """

    return bool(
        re.search(
            r"(?i)<\s*(?:script|iframe|object|embed)\b",
            output,
        )
    )


def html_has_event_handler(output: str) -> bool:
    """
    Detect attributes such as:

        onclick=
        onload=
        onerror=
        onmouseover=

    """

    return bool(
        re.search(
            r"(?i)\bon[a-zA-Z0-9_-]*\s*=",
            output,
        )
    )


def sql_has_metachar(output: str) -> bool:

    if "'" in output:
        return True

    if '"' in output:
        return True

    if ";" in output:
        return True

    if "--" in output:
        return True

    if "/*" in output:
        return True

    if re.search(r"(?i)\bunion\b", output):
        return True

    if re.search(r"(?i)\bor\s+1\s*=\s*1\b", output):
        return True

    return False


def shell_has_metachar(output: str) -> bool:

    if re.search(r"[;&|`<>]", output):
        return True

    if "$(" in output:
        return True

    if "${" in output:
        return True

    return False


def channel_rule_violation(channel: str, output: str):
    """
    Apply channel-specific rules in the exact order
    specified by the question.

    Returns the first reason or None.
    """

    # --------------------------------------------------------
    # HTML
    # --------------------------------------------------------
    if channel == "html":

        if html_has_script_tag(output):
            return "SCRIPT_TAG"

        if html_has_event_handler(output):
            return "EVENT_HANDLER"

        if contains_dangerous_scheme(output):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, output)

        for url in urls:
            if url_has_dangerous_scheme(url):
                return "DANGEROUS_SCHEME"

        for url in urls:
            if url_is_external_exfil(url):
                return "EXTERNAL_EXFIL"

        return None

    # --------------------------------------------------------
    # MARKDOWN
    # --------------------------------------------------------
    if channel == "markdown":

        if contains_dangerous_scheme(output):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, output)

        for url in urls:
            if url_has_dangerous_scheme(url):
                return "DANGEROUS_SCHEME"

        for url in urls:
            if url_is_external_exfil(url):
                return "EXTERNAL_EXFIL"

        return None

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------
    if channel == "url":

        if contains_dangerous_scheme(output):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, output)

        for url in urls:
            if url_has_dangerous_scheme(url):
                return "DANGEROUS_SCHEME"

        for url in urls:
            if url_is_external_exfil(url):
                return "EXTERNAL_EXFIL"

        return None

    # --------------------------------------------------------
    # SQL
    # --------------------------------------------------------
    if channel == "sql":

        if sql_has_metachar(output):
            return "SQL_METACHAR"

        return None

    # --------------------------------------------------------
    # SHELL
    # --------------------------------------------------------
    if channel == "shell":

        if shell_has_metachar(output):
            return "SHELL_METACHAR"

        return None

    return None



@app.post("/sanitize-output")
def sanitize_output(payload: Any):

    # ========================================================
    # 1. INVALID_SCHEMA
    # ========================================================

    if not isinstance(payload, dict):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if "channel" not in payload:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if "output" not in payload:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    channel = payload["channel"]
    output = payload["output"]

    # IMPORTANT: type-check BEFORE set membership
    if not isinstance(channel, str):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if channel not in ALLOWED_CHANNELS:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if not isinstance(output, str):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if len(output) > 20000:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    # ========================================================
    # 2. ENCODED_PAYLOAD
    # ========================================================

    decoded = decode_once(output)

    if decoded != output:

        decoded_violation = channel_rule_violation(
            channel,
            decoded
        )

        if decoded_violation is not None:
            return {
                "safe": False,
                "reason": "ENCODED_PAYLOAD"
            }

    # ========================================================
    # 3. ORIGINAL OUTPUT
    # ========================================================

    violation = channel_rule_violation(
        channel,
        output
    )

    if violation is not None:
        return {
            "safe": False,
            "reason": violation
        }

    return {
        "safe": True,
        "reason": "SAFE"
    }