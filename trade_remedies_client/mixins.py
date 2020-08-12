from .client import Client


class TradeRemediesAPIClientMixin:
    """
    Adds two methods to the object implementing this mixin:
    trusted_client
        returns a trusted API client (no user provided).
    client
        receives a user and creates a client with that user's token
    """

    @property
    def trusted_client(self):
        try:
            return self.__trusted_client
        except AttributeError:
            self.__trusted_client = Client()
        return self.__trusted_client

    def client(self, user):
        client = Client(user.token)
        return client

    def cached_client(self, user=None):
        return Client(user, use_cache=True)
