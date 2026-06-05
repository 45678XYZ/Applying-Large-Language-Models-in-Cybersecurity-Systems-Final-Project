from scripts.demo_scenarios import build_demo_report, list_scenarios


def test_phase6_demo_scenarios_have_expected_grades():
    expected = {
        "clean_network": "A",
        "risky_iot": "C",
        "vulnerable_router": "D",
    }

    scenarios = list_scenarios()
    assert [scenario.scenario_id for scenario in scenarios] == list(expected)

    for scenario in scenarios:
        report = build_demo_report(scenario.scenario_id)
        assert report.overall_grade == expected[scenario.scenario_id]
        assert report.summary_markdown


def test_vulnerable_router_demo_cites_a_real_cve():
    report = build_demo_report("vulnerable_router")
    cve_ids = {
        cve.cve_id
        for finding in report.findings
        for cve in finding.related_cves
    }

    assert "CVE-2018-5371" in cve_ids
    assert "CVE-2018-5371" in report.summary_markdown
