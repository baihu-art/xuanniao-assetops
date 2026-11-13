import pytest

from assetops.analysis.scoring import priority_for_score, score_asset, top_targets
from assetops.models.asset import Asset, Observation


def asset_with(**evidence):
    return Asset(observations=[Observation(id="e1", run_id="r", source="httpx", evidence=evidence)])


def test_maximum_and_dimensions():
    result = score_asset(asset_with(host="test.example.com", port=3306, title="Admin", status_code=200), "r")
    assert result["score"] == 97
    assert result["dimensions"] == dict(exposure=30, technical_risk=25, data_value=20, attack_surface=12, uniqueness=10)
    assert result["rule_max"] == 97
    assert result["theoretical_max"] == 100
    assert result["priority"] == "high"
    assert result["input_observation_ids"] == ["e1"]


@pytest.mark.parametrize("status,title,points", [(200, "WAF拦截", 20), (200, "ok", 30), (301,"",25), (302,"",25), (401,"",20), (403,"",15), (503,"",10), (500,"",0)])
def test_exposure(status, title, points):
    assert score_asset(asset_with(status_code=status, title=title), "r")["dimensions"]["exposure"] == points


@pytest.mark.parametrize("server,title,tech,points", [("nginx","Welcome to nginx",[],22), ("ZLMediaKit","",[],25), ("OpenResty","",[],20), ("Tengine","",[],18), ("tencent-cos","",[],10), ("TosServer","",[],10), ("stgw","",[],8), ("other","",["React"],15), ("","",[],5)])
def test_technical_branch_order(server, title, tech, points):
    result = score_asset(asset_with(server=server,title=title,tech=tech), "r")
    assert result["dimensions"]["technical_risk"] == points
    assert not any("已知CVE" in reason for reason in result["reasons"])


@pytest.mark.parametrize("port,points", [("9000",12),("8080",8),("8443",8),("8000",5),("3000",5),("80",5),("443",5),("",5)])
def test_width(port, points):
    assert score_asset(asset_with(port=port), "r")["dimensions"]["attack_surface"] == points


@pytest.mark.parametrize("score,priority", [(34,"low"),(35,"medium"),(59,"medium"),(60,"high")])
def test_priority_threshold(score, priority):
    assert priority_for_score(score) == priority


def test_current_run_active_priority_no_snapshot_and_no_analysis():
    asset = Asset(host="test.old.example", title="Admin", port="3306", server="ZLMediaKit", observations=[
        Observation(id="old",run_id="other",source="httpx",evidence={"status_code":200,"title":"Admin"}),
        Observation(id="passive",run_id="r",source="fofa",last_seen_at="2030",evidence={"status_code":200,"server":"OpenResty"}),
        Observation(id="a1",run_id="r",source="httpx",last_seen_at="2020",evidence={"status_code":403,"title":"older"}),
        Observation(id="a2",run_id="r",source="httpx",last_seen_at="2021",evidence={"status_code":401,"title":"current"}),
        Observation(id="analysis",run_id="r",source="analysis",evidence={"host":"test.example.com","port":3306}),
    ])
    result = score_asset(asset, "r")
    assert result["title"] == "current"
    assert result["host"] == result["port"] == ""
    assert result["dimensions"]["exposure"] == 20
    assert result["input_observation_ids"] == ["a2", "passive"]
    assert score_asset(asset, "r") == result
    assert score_asset(asset, "empty")["input_observation_ids"] == []


def test_url_identity_and_top20():
    result = score_asset(asset_with(url="https://a.example.com/", status_code=200), "r")
    assert (result["host"],result["port"]) == ("a.example.com","443")
    entries = [{"asset_id":str(i),"host":f"h{i // 2}","score":i} for i in range(50)]
    top = top_targets(entries)
    assert len(top) == 20
    assert top[0]["score"] == 49
    assert len({r["host"] for r in top}) == 20
    assert top_targets(entries,0) == []
