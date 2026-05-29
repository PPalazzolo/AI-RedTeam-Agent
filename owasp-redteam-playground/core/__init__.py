"""Core modules for the red team webapp.

Each module owns a single concern:
- config       : on-disk API key + settings (~/.owasp-redteam/)
- models       : selectable OpenAI model list
- scenarios    : manifest of attack scenarios
- agent_factory: build target agent from settings OR custom code
- detector     : keyword-based vulnerability detection
- runner       : orchestrate a run, emit progress events
- report       : render standalone HTML report
"""

DOCS_REGISTRY = [
    {
        "id": "how-it-works",
        "title": "How it works",
        "subtitle": "A friendly tour of the 3 Python files",
        "type": "html",
        "path": "../redteam/how_it_works.html",
    },
    {
        "id": "architecture",
        "title": "Architecture",
        "subtitle": "System design, components, and data flow",
        "type": "markdown",
        "path": "../redteam/docs/ARCHITECTURE.md",
    },
    {
        "id": "test-scenario-design",
        "title": "Test scenario design",
        "subtitle": "How to author new attack scenarios",
        "type": "markdown",
        "path": "../redteam/docs/TEST_SCENARIO_DESIGN.md",
    },
    {
        "id": "threat-model",
        "title": "Threat model",
        "subtitle": "What the framework is testing for",
        "type": "markdown",
        "path": "../redteam/docs/THREAT_MODEL.md",
    },
]
