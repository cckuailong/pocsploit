class ToolkitBaseException(Exception):
    pass


class ToolkitConnectionException(Exception):
    pass


class ToolkitDataException(ToolkitBaseException):
    pass


class ToolkitMissingPrivileges(ToolkitBaseException):
    pass


class ToolkitUserQuitException(ToolkitBaseException):
    pass


class ToolkitSystemException(ToolkitBaseException):
    pass


class ToolkitValueException(ToolkitBaseException):
    pass


class ToolkitPluginException(ToolkitBaseException):
    pass


class RegisterException(Exception):
    pass


class RegisterValueException(RegisterException):
    pass


class RegisterDataException(RegisterException):
    pass


class RegisterMutexException(RegisterException):
    pass
