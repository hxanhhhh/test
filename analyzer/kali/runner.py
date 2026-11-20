from analyzer.kali.orchestrator import run_agent, run_pipeline
from analyzer.kali.persist import save_orchestrator_result
from analyzer.models import TestProject


def run_kali_pentest(
    target: str = "127.0.0.1",
    url: str | None = None,
    cookie: str = "",
    use_agent: bool = True,
    max_steps: int = 6,
    project: TestProject | None = None,
    project_name: str = "CLI Kali",
    save: bool = True,
    on_step=None,
) -> dict:
    runner = run_agent if use_agent else run_pipeline
    kwargs = dict(target=target, url=url, cookie=cookie, on_step=on_step)
    if use_agent:
        kwargs["max_steps"] = max_steps

    result = runner(**kwargs)
    scan = None

    if save and result.get("lab", True):
        proj = project
        if proj is None:
            proj, _ = TestProject.objects.get_or_create(
                name=project_name,
                defaults={"description": "Kết quả chạy pentest qua Kali/MCP."},
            )
        scan = save_orchestrator_result(proj, result)

    return {
        "result": result,
        "scan": scan,
        "scan_id": scan.pk if scan else None,
        "summary": result.get("summary", {}),
    }
