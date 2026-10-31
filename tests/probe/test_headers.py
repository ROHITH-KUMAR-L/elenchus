"""Own header and cookie checks are deterministic over one response."""

from probe.headers import check_response
from probe.oracles import Response

SECURE = (
    "HTTP/1.1 200\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: DENY\r\n"
    "Set-Cookie: SID=abc; Path=/; HttpOnly; SameSite=Strict\r\n"
)


def names(response: Response) -> set[tuple[str, int]]:
    return {(f.header_name, f.cwe) for f in check_response(response)}


def test_a_fully_protected_response_has_no_findings():
    assert check_response(Response(200, SECURE, "")) == []


def test_missing_nosniff_is_flagged():
    headers = SECURE.replace("X-Content-Type-Options: nosniff\r\n", "")
    assert ("X-Content-Type-Options", 693) in names(Response(200, headers, ""))


def test_frame_protection_passes_with_frame_ancestors_in_csp():
    headers = SECURE.replace("X-Frame-Options: DENY\r\n", "Content-Security-Policy: frame-ancestors 'none'\r\n")
    assert ("X-Frame-Options", 1021) not in names(Response(200, headers, ""))


def test_no_frame_protection_is_flagged_as_clickjacking():
    headers = SECURE.replace("X-Frame-Options: DENY\r\n", "")
    assert ("X-Frame-Options", 1021) in names(Response(200, headers, ""))


def test_each_cookie_is_checked_on_its_own():
    headers = (
        "HTTP/1.1 200\r\n"
        "X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n"
        "Set-Cookie: A=1; Path=/\r\n"
        "Set-Cookie: B=2; Path=/; HttpOnly; SameSite=Lax\r\n"
    )
    found = names(Response(200, headers, ""))
    assert ("A", 1004) in found and ("A", 1275) in found
    assert ("B", 1004) not in found and ("B", 1275) not in found


def test_header_names_are_matched_case_insensitively():
    headers = "HTTP/1.1 200\r\nx-content-type-options: nosniff\r\nx-frame-options: deny\r\n"
    assert check_response(Response(200, headers, "")) == []
