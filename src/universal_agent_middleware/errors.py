class UAMError(Exception):
    """Base error for Universal Agent Middleware."""


class AuthorizationError(UAMError):
    pass


class WorkspaceError(UAMError):
    pass


class PathPolicyError(UAMError):
    pass


class ContractError(UAMError):
    pass


class ProtocolError(UAMError):
    pass
