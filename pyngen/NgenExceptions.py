import json


class NgenError(Exception):
    detail = "Ngen Exception"

    def __str__(self):
        return self.detail

    def __repr__(self):
        return self.detail


class UnauthorizedNgenError(NgenError):
    detail = "Invalid Api Key"


class UnexpectedError(NgenError):
    _detail = '\n\n - Error Code {}\n - Error Message:\n{}'

    def __init__(self, code, msg):
        self.code = code
        self.msg = msg

    @property
    def detail(self):
        # json.dumps(json.loads(self.msg), indent=4, sort_keys=True))
        return self._detail.format(self.code, self.msg)


class SchemeNotSettedError(NgenError):
    _detail = '\n\n - Error Message:\n{}'

    def __init__(self, msg):
        self.msg = msg

    @property
    def detail(self):
        # json.dumps(json.loads(self.msg), indent=4, sort_keys=True))
        return self._detail.format(self.msg)



class NewIncidentFieldError(NgenError):
    _detail = 'Error Message:\n{}'

    def __init__(self,  msg):
        self.msg = msg

    @property
    def detail(self):
        # json.dumps(json.loads(self.msg), indent=4, sort_keys=True))
        return self._detail.format(self.msg)



class NotFoundError(NgenError):
    detail = "Object not found"
