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



class NewEventFieldError(NgenError):
    _detail = '\n\n - Event field error. Error Message:\n{}\n - Data sent:\n{}'

    def __init__(self, data, msg):
        self.data = data
        self.msg = msg

    @property
    def detail(self):
        # json.dumps(json.loads(self.msg), indent=4, sort_keys=True))
        return self._detail.format(self.msg, self.data)


class NewEventTypeFieldError(NgenError):
    _detail = '\n\n - Event type field error. Error Message:\n{}\n - Data sent:\n{}'

    def __init__(self, data, msg):
        self.data = data
        self.msg = msg

    @property
    def detail(self):
        # json.dumps(json.loads(self.msg), indent=4, sort_keys=True))
        return self._detail.format(self.msg, self.data)


class NewEventTypeDeactivatedError(NgenError):
    _detail = '\n\n - Event type is deactivated. Error Message:\n{}\n - Data sent:\n{}'

    def __init__(self, data, msg):
        self.data = data
        self.msg = msg

    @property
    def detail(self):
        # json.dumps(json.loads(self.msg), indent=4, sort_keys=True))
        return self._detail.format(self.msg, self.data)


class NewEventError(NgenError):
    _detail = 'Error Message:\n{}'

    def __init__(self,  msg):
        self.msg = msg

    @property
    def detail(self):
        # json.dumps(json.loads(self.msg), indent=4, sort_keys=True))
        return self._detail.format(self.msg)



# class NotFoundError(NgenError):
#     detail = "Object not found"
