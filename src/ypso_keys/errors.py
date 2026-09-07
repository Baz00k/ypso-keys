class ToolError(Exception):
    """Only static, non-secret diagnostic text may enter this exception."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)
