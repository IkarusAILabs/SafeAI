from safeai.analyzers.capability.analyzer import CapabilityAnalyzer


def _run_analyzer(code, rules=None):
    file_cache = {"test.py": code}
    rules = rules or [
        {"id": "CAP_docker", "severity": "medium", "owasp_llm": "LLM06"},
        {"id": "CAP_kubernetes", "severity": "medium", "owasp_llm": "LLM06"},
        {"id": "CAP_redis", "severity": "medium", "owasp_llm": "LLM06"},
        {"id": "CAP_s3", "severity": "medium", "owasp_llm": "LLM06"},
        {"id": "CAP_slack", "severity": "medium", "owasp_llm": "LLM06"},
        {"id": "CAP_ms_teams", "severity": "medium", "owasp_llm": "LLM06"},
        {"id": "CAP_jira", "severity": "low", "owasp_llm": "LLM06"},
        {"id": "CAP_browser_playwright", "severity": "medium", "owasp_llm": "LLM06"},
        {"id": "CAP_browser_selenium", "severity": "medium", "owasp_llm": "LLM06"},
        {"id": "CAP_browser_use", "severity": "medium", "owasp_llm": "LLM06"},
        {"id": "CAP_gcp", "severity": "medium", "owasp_llm": "LLM06"},
    ]
    analyzer = CapabilityAnalyzer()
    return analyzer.run(file_cache, rules)


def test_docker_import():
    findings = _run_analyzer("import docker\nclient = docker.DockerClient()\n")
    assert any(f["rule_id"] == "CAP_docker" for f in findings)


def test_docker_from_import():
    findings = _run_analyzer("from docker import DockerClient\n")
    assert any(f["rule_id"] == "CAP_docker" for f in findings)


def test_kubernetes_import():
    findings = _run_analyzer("from kubernetes import client\nclient.list_namespaced_pod('default')\n")
    assert any(f["rule_id"] == "CAP_kubernetes" for f in findings)


def test_kubernetes_config():
    findings = _run_analyzer("from kubernetes.config import load_kube_config\n")
    assert any(f["rule_id"] == "CAP_kubernetes" for f in findings)


def test_redis_import():
    findings = _run_analyzer("import redis\nr = redis.Redis(host='localhost')\n")
    assert any(f["rule_id"] == "CAP_redis" for f in findings)


def test_redis_client():
    findings = _run_analyzer("from redis import StrictRedis\nr = StrictRedis()\n")
    assert any(f["rule_id"] == "CAP_redis" for f in findings)


def test_s3_boto3():
    findings = _run_analyzer("import boto3\ns3 = boto3.client('s3')\n")
    assert any(f["rule_id"] == "CAP_s3" for f in findings)


def test_s3_resource():
    findings = _run_analyzer("from boto3 import resource\ns3 = resource('s3')\n")
    assert any(f["rule_id"] == "CAP_s3" for f in findings)


def test_slack_sdk():
    findings = _run_analyzer("from slack_sdk import WebClient\nclient = WebClient(token='xoxb-...')\n")
    assert any(f["rule_id"] == "CAP_slack" for f in findings)


def test_slack_socket():
    findings = _run_analyzer("from slack import SocketModeClient\n")
    assert any(f["rule_id"] == "CAP_slack" for f in findings)


def test_jira_import():
    findings = _run_analyzer("from jira import JIRA\njira = JIRA(server='https://example.atlassian.net')\n")
    assert any(f["rule_id"] == "CAP_jira" for f in findings)


def test_teams_import():
    findings = _run_analyzer("import teams\nclient = teams.TeamsClient()\n")
    assert any(f["rule_id"] == "CAP_ms_teams" for f in findings)


def test_teams_from_import():
    findings = _run_analyzer("from teams import TeamsClient\nclient = TeamsClient(token='abc')\n")
    assert any(f["rule_id"] == "CAP_ms_teams" for f in findings)


def test_teams_sdk_reference():
    findings = _run_analyzer("from teams_sdk import TeamsClient\nclient = TeamsClient(token='abc')\n")
    assert any(f["rule_id"] == "CAP_ms_teams" for f in findings)


def test_teams_name_is_not_a_false_positive_on_substrings():
    findings = _run_analyzer("myteamscore = 42\nprint(myteamscore)\n")
    assert all(f["rule_id"] != "CAP_ms_teams" for f in findings)


def test_jira_client():
    findings = _run_analyzer("import jira\njira.Client()\n")
    assert any(f["rule_id"] == "CAP_jira" for f in findings)


def test_browser_playwright():
    findings = _run_analyzer("from playwright.sync_api import sync_playwright\n")
    assert any(f["rule_id"] == "CAP_browser_playwright" for f in findings)


def test_browser_selenium():
    findings = _run_analyzer("from selenium import webdriver\n")
    assert any(f["rule_id"] == "CAP_browser_selenium" for f in findings)


def test_browser_use():
    findings = _run_analyzer("from browser_use import Agent\n")
    assert any(f["rule_id"] == "CAP_browser_use" for f in findings)


def test_gcp_cloud():
    findings = _run_analyzer("from google.cloud import storage\nclient = storage.Client()\n")
    assert any(f["rule_id"] == "CAP_gcp" for f in findings)


def test_gcp_bigquery():
    findings = _run_analyzer("from google.cloud import bigquery\nclient = bigquery.Client()\n")
    assert any(f["rule_id"] == "CAP_gcp" for f in findings)


def test_no_false_positive_on_unrelated_code():
    findings = _run_analyzer("import os\nprint('hello')\n")
    new_caps = {f["rule_id"] for f in findings if f["rule_id"].startswith("CAP_")}
    assert new_caps <= {"CAP_filesystem"}, "unrelated code should not trigger new capabilities"


def test_multiple_capabilities():
    code = (
        "import docker\n"
        "import redis\n"
        "from slack_sdk import WebClient\n"
    )
    findings = _run_analyzer(code)
    rule_ids = {f["rule_id"] for f in findings}
    assert "CAP_docker" in rule_ids
    assert "CAP_redis" in rule_ids
    assert "CAP_slack" in rule_ids


def test_deduplication_same_line():
    code = "import docker\n"
    findings = _run_analyzer(code)
    docker_findings = [f for f in findings if f["rule_id"] == "CAP_docker"]
    assert len(docker_findings) == 1
