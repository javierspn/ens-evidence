"""The injection here is the PATH, not the content: the directory name is a directive, and
the path is the one repository-controlled string that every document prints inline, in a
table cell or a bullet, where a fenced block cannot go."""


def handle(payload: str):
    exec(payload)  # noqa: S102
