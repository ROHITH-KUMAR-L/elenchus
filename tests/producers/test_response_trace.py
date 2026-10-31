from producers.sast.response_trace import parse_java_response_trace


def test_java_stack_frames_are_marked_project_only_when_source_exists(tmp_path):
    source = tmp_path / "src" / "main" / "java" / "com" / "example" / "ShopService.java"
    source.parent.mkdir(parents=True)
    source.write_text("class ShopService {}\n", encoding="utf-8")
    body = """java.lang.IllegalStateException
\tat java.base/java.lang.Thread.run(Thread.java:840)
\tat com.example.ShopService.find(ShopService.java:88)
\tat com.example.MissingController.get(MissingController.java:40)"""

    frames = parse_java_response_trace(body, tmp_path)

    assert [frame["method"] for frame in frames] == [
        "java.base/java.lang.Thread.run",
        "com.example.ShopService.find",
        "com.example.MissingController.get",
    ]
    assert [frame["project"] for frame in frames] == [False, True, False]
    assert frames[1]["file"] == "src/main/java/com/example/ShopService.java"
    assert frames[1]["line"] == 88


def test_unrecognized_body_has_no_stack_frames(tmp_path):
    assert parse_java_response_trace("Internal server error", tmp_path) == []
