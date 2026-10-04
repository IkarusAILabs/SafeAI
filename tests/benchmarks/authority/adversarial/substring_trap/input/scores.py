"""High score tracker. Nothing agent-related in this module."""
myteamscore = 42


def team_summary(scores):
    """Summarize team scores (no Teams integration here)."""
    return sum(scores.values()) / max(len(scores), 1)


print(myteamscore, team_summary({"a": 1}))
