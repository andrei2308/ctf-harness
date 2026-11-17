"""Test doubles for 'a tool printed this'.

The evidence store refuses a value the producing command itself carried (the
model printing its own guess), so a fake tool cannot simply echo its argument:
the scripted model sends the text hex-wrapped with `hide`, and the fake tool
prints it back with `shown`."""


def hide(text) -> str:
    return "hex:" + str(text).encode("utf-8", "surrogatepass").hex()


def shown(text) -> bytes:
    text = str(text)
    if text.startswith("hex:"):
        return bytes.fromhex(text[4:])
    return text.encode("utf-8", "surrogatepass")
