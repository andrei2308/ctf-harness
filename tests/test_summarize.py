"""Heuristic output summarizer: keep signal, cut tokens, never lose a flag (the
full bytes still reach the evidence store separately)."""

from harness.agents.tools import summarize_output


def test_small_output_passes_through():
    data = b"short output\nline2\n"
    assert summarize_output(data, limit=1000) == data.decode()


def test_large_output_keeps_interesting_lines_and_tails():
    noise = ("noise line that is boring\n" * 5000).encode()
    data = noise + b"the password is hunter2\n" + b"0xdeadbeefcafe here\n" + noise
    out = summarize_output(data, limit=2000)
    assert len(out) < len(data)
    assert "password is hunter2" in out       # interest filter kept it
    assert "bytes total" in out                # size note present


def test_interesting_lines_deduped():
    # Repeated interesting line in the MIDDLE (head/tail are verbatim by design).
    data = (b"boring\n" * 3000) + (b"error: boom\n" * 1000) + (b"boring\n" * 3000)
    out = summarize_output(data, limit=1000)
    assert len(out) < len(data)
    # the interest section keeps the repeated error line once, not 1000 times
    assert out.count("error: boom") <= 3
