# trade-remedies-client

Trade Remedies API Python Client


## Calling API methods

### Adhoc API calls


    from trade_remedies_client.client import Client
    client = Client(token)
    # making api calls:
    case = client.get_case(case_id)
    cases = client.get_cases()


Note that if the client is instantiated without a token, the trusted user token will be used

    trusted_client = Client()


This is only useful for requesting non authenticated or public endpoints (like authentication, registration etc).
Do not use the client without a token for requests that require a user, as you will not get back any results.


## Mixin

The mixin TradeRemediesAPIClientMixin can be added to any Django view (or object) and will add
a ``trusted_client`` property and a ``client()`` method. The latter receives the user model as input and extracts
the token from it.


## How it works


The API client is a small-ish object which serves as a dynamic proxy to the functions defined in ``lib.py``.
When an api method is requested from the client it is lazy bound to the client and called.

The functions in lib, although being regular python functions, do receive ``self`` as a first argument to support being
bound to the client object at runtime.
Adding new API calls is a matter of adding those functions into ``lib.py``.
The functions can support their own caching if and when required. By being bound to the client they can access
self.token for the current user token


## Updating the client


To add new API calls, simply add the function in the ``lib.py`` file and ensure the first argumnet is ``self``.
When complete you can test locally by issuing::

    python setup.py sdist

And update the front ends using::

    pip install /path/to/client/dist/trade_remedies_client.x


At this stage, the built client is part of each repository (public/caseworker).
Assuming the directory structure of the entire project consists of each repository at the same level::


    /path/trade-remedies-public/
    /path/trade-remedies-caseworker/
    /path/trade-remedies-client/
    /path/trade-remedies-docker/


Issuing ``make local_deploy`` from within the client repo directory will build the client and copy the results
into each repository as required. Following that a rebuild of the containers is needed as the client is
installed on build time. If not using docker it is possible to also update the local virtual env.



In future, if the client ends up on pypi, then it is also deployable by issuing:

    make deploy
