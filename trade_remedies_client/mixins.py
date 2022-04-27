from .client import Client
import inspect
import re

class TradeRemediesAPIClientMixin:
    """
    Adds two methods to the object implementing this mixin:
    trusted_client
        returns a trusted API client (no user provided).
    client
        receives a user and creates a client with that user's token
    """
    def load_stack(self):
        originating_details = {
            "originating_file": "",
            "originating_file_line": "",
            "originating_method": "",
            "originating_code": "",
            "originating_class_name": "",
        }
        try:
            current_stack = inspect.stack()
            originating_details["originating_file"] = current_stack[2][1]
            originating_details["originating_file_line"] = current_stack[2][2]
            originating_details["originating_method"] = current_stack[2][3]
            originating_details["originating_code"] = re.sub(
                r"[\n\t\s]*",
                "",
                current_stack[2][4][0]
            )
            originating_details["originating_class_name"] = type(self).__name__
        except Exception as e:
            raise e
        finally:
            del current_stack
            return originating_details

    @property
    def trusted_client(self):
        try:
            trusted_client = self.__trusted_client
        except AttributeError:
            trusted_client = Client()
        setattr(trusted_client, "originating_details", self.load_stack())
        self.__trusted_client = trusted_client
        return self.__trusted_client

    def client(self, user):
        client = Client(user.token)
        setattr(client, "originating_details", self.load_stack())
        return client
