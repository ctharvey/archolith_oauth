from archolith_oauth.cli import run


def _set_env(monkeypatch, tmp_path):
    values = {
        "CLI_OAUTH_ISSUER": "https://auth.example.com/app",
        "CLI_OAUTH_RESOURCE": "https://api.example.com/mcp",
        "CLI_OAUTH_SCOPES": "app:read app:write",
        "CLI_OAUTH_DEFAULT_SCOPES": "app:read",
        "CLI_OAUTH_DATA_DIR": str(tmp_path / "oauth"),
        "CLI_OAUTH_CONSENT_SECRET": "top-secret-value-that-is-long-enough",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_show_config_is_redacted(monkeypatch, tmp_path, capsys):
    _set_env(monkeypatch, tmp_path)
    assert run(["--prefix", "CLI_OAUTH_", "show-config", "--json"]) == 0
    output = capsys.readouterr().out
    assert "consent_secret_configured" in output
    assert "top-secret-value" not in output


def test_preflight_cli(monkeypatch, tmp_path, capsys):
    _set_env(monkeypatch, tmp_path)
    assert (
        run(
            [
                "--prefix",
                "CLI_OAUTH_",
                "preflight",
                "--require-consent-secret",
            ]
        )
        == 0
    )
    assert "configuration: OK" in capsys.readouterr().out
