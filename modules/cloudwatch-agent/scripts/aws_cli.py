import json,os,re,subprocess,time
REGION = "ap-northeast-2"

class DeploymentError(RuntimeError):
    """A safe-to-display error with no environment values or raw AWS responses."""

class AWSCLIError(DeploymentError):
    def __init__(self, service, operation, code, missing=False, diagnostics=None):
        self.code, self.missing = code, missing
        self.diagnostics = diagnostics
        super().__init__(f"AWS {service} {operation} failed ({code}).")

class AWSCLI:
    def __init__(self, region=REGION):
        self.version_checked = False
        self.region = region

    @staticmethod
    def deploy_process(command, env):
        """Keep CloudShell responsive without exposing raw deployment output."""
        deadline = time.monotonic() + 1800
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, env=env) as process:
            while True:
                try:
                    stdout, stderr = process.communicate(timeout=min(30, max(1, deadline - time.monotonic())))
                    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                except subprocess.TimeoutExpired:
                    if time.monotonic() >= deadline:
                        process.kill()
                        process.communicate()
                        raise DeploymentError("CloudFormation deployment exceeded 30 minutes; inspect stack status before retrying.")
                    print("[waiting_for_stack]", flush=True)

    def call(self, service, operation, *args):
        env = dict(os.environ, AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off")
        if not self.version_checked:
            try:
                result = subprocess.run(["aws", "--version"], capture_output=True,
                                        text=True, env=env, timeout=30)
            except (OSError, subprocess.SubprocessError) as exc:
                raise DeploymentError("AWS CLI v2 is required in CloudShell.") from exc
            if result.returncode or "aws-cli/2." not in result.stdout + result.stderr:
                raise DeploymentError("AWS CLI v2 is required in CloudShell.")
            self.version_checked = True
        command = ["aws", service, operation, *map(str, args), "--region", self.region,
                   "--output", "json", "--no-cli-pager", "--no-paginate",
                   "--cli-connect-timeout", "5", "--cli-read-timeout", "30"]
        try:
            result = (self.deploy_process(command, env) if operation == "deploy" else
                      subprocess.run(command, capture_output=True, text=True, env=env, timeout=90))
        except (OSError, subprocess.SubprocessError) as exc:
            raise DeploymentError(f"AWS {service} {operation} could not finish; inspect current resource state before retrying.") from exc
        if result.returncode:
            match = re.search(r"\(([A-Za-z0-9_.-]+)\)", result.stderr)
            code = match.group(1) if match else "CLIError"
            missing = code in {"ResourceNotFoundException", "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}
            if (service, operation) == ("cloudformation", "describe-stacks"):
                missing = code == "ValidationError" and bool(re.search(r"Stack with id .* does not exist", result.stderr))
            diagnostics = None
            if (service, operation) == ("cloudformation", "deploy"):
                diagnostics = {"stdout": result.stdout[:131072], "stderr": result.stderr[:131072]}
            raise AWSCLIError(service, operation, code, missing, diagnostics)
        # cloudformation deploy prints progress even when --output json is set.
        if operation == "deploy":
            return {}
        try:
            return json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError as exc:
            raise DeploymentError(f"AWS {service} {operation} returned invalid JSON.") from exc

def private_write(path, content):
    data = content.encode("utf-8") if isinstance(content, str) else content
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o600)

def private_json(path, value):
    private_write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")
