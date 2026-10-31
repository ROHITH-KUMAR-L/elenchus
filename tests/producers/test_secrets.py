"""The own secrets and weak-crypto pass, on small Java sources.

Each weak pattern has a safe twin, so a rule that flags too much also fails.
"""

from textwrap import dedent

from producers.sast.secrets import find_secrets
from producers.sast.spring_routes import _parse_files


def sites(tmp_path, source):
    (tmp_path / "C.java").write_text(dedent(source))
    files = _parse_files(tmp_path)
    return {(f.cwe, f.rule, f.line) for f in find_secrets(files)}


def rules(tmp_path, source):
    return {(cwe, rule) for cwe, rule, _ in sites(tmp_path, source)}


def test_weak_hash_is_flagged_and_strong_hash_is_not(tmp_path):
    found = rules(tmp_path, """
        class C {
            void a() throws Exception { MessageDigest.getInstance("MD5"); }
            void b() throws Exception { MessageDigest.getInstance("SHA-256"); }
        }
        """)
    assert (327, "weak_hash") in found


def test_strong_hash_alone_is_not_flagged(tmp_path):
    found = rules(tmp_path, """
        class C { void b() throws Exception { MessageDigest.getInstance("SHA-256"); } }
        """)
    assert found == set()


def test_weak_cipher_prefix_and_ecb_mode(tmp_path):
    found = rules(tmp_path, """
        class C {
            void a() throws Exception { Cipher.getInstance("DES"); }
            void b() throws Exception { Cipher.getInstance("AES/ECB/PKCS5Padding"); }
        }
        """)
    assert found == {(327, "weak_cipher")}


def test_strong_cipher_is_not_flagged(tmp_path):
    found = rules(tmp_path, """
        class C { void a() throws Exception { Cipher.getInstance("AES/GCM/NoPadding"); } }
        """)
    assert found == set()


def test_weak_random_constructor_and_math_random(tmp_path):
    found = rules(tmp_path, """
        class C {
            void a() { Random r = new Random(); }
            void b() { double d = Math.random(); }
        }
        """)
    assert found == {(330, "weak_random")}


def test_secure_random_is_not_flagged(tmp_path):
    found = rules(tmp_path, """
        class C { void a() { SecureRandom r = new SecureRandom(); } }
        """)
    assert found == set()


def test_hardcoded_secret_is_flagged_by_name_and_literal(tmp_path):
    found = rules(tmp_path, """
        class C {
            private String password = "hunter2";
            private String apiKey = "abc123";
        }
        """)
    assert found == {(798, "hardcoded_secret")}


def test_non_secret_name_and_non_literal_value_are_not_flagged(tmp_path):
    found = rules(tmp_path, """
        class C {
            private String username = "bob";
            private String password = System.getenv("PW");
        }
        """)
    assert found == set()
