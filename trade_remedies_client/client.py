"""



"""
import types
import hashlib
import requests
from django.conf import settings
from django.core.cache import cache
from . import lib
from .exceptions import APIException

ENVIRONMENT_KEY = getattr(settings, "ENVIRONMENT_KEY")
API_URL = getattr(settings, "API_URL")
HEALTH_CHECK_TOKEN = getattr(settings, "HEALTH_CHECK_TOKEN")


class Client:
    def __init__(self, token=None, **kwargs):
        self._method = None
        self.token = token or HEALTH_CHECK_TOKEN
        self.use_cache = kwargs.get("use_cache", False)
        for k in kwargs:
            setattr(self, k, kwargs[k])

    def __getattr__(self, key):
        try:
            return super().__getattribute__(key)
        except AttributeError:
            setattr(self, key, types.MethodType(getattr(lib, key), self))
            # self._method = getattr(lib, key)
            return getattr(self, key)  # self._method

    def headers(self, extra_headers=None):
        _headers = {
            "Authorization": f"Token {self.token}",
            "X-Origin-Environment": ENVIRONMENT_KEY,
            "X-User-Agent": "",
            "X-Forwarded-For": "",
        }
        if extra_headers and isinstance(extra_headers, dict):
            _headers.update(extra_headers)
        return _headers

    def get_url(self, path):
        """
        Construct a full API url
        """
        return f"{API_URL}{path}"

    def get_from_cache(self, key):
        return cache.get(key)

    def set_cache(self, key, value, ttl):
        cache.set(key, value, ttl)

    def md5_hash(self, *args):
        md5 = hashlib.md5()
        for arg in args:
            if arg:
                md5.update(str(arg).encode("utf8"))
        return md5.hexdigest()

    def get_resource(self, url, params=None, stream=None):
        extra_kwargs = {"stream": stream} if stream is not None else {}
        _headers = self.headers()
        response = requests.get(url, headers=_headers, params=params, **extra_kwargs)
        response.raise_for_status()
        return response

    def get(self, url, params=None, extra_headers=None, fields=None):
        params = params or {}
        if fields:
            params["fields"] = fields
        _headers = self.headers(extra_headers=extra_headers)
        response = requests.get(url, headers=_headers, params=params)
        response.raise_for_status()
        return response.json()

    def get_one(self, path, params=None, extra_headers=None, fields=None):
        _url = self.get_url(path)
        response = self.get(_url, params=params, extra_headers=None, fields=fields)
        if "result" in response.get("response", {}):
            return response.get("response", {}).get("result")
        else:
            raise Exception("Invalid response")

    def get_many(self, path, params=None, fields=None):
        _url = self.get_url(path)
        response = self.get(_url, params=params, fields=fields)
        if "results" in response.get("response", {}):
            return response.get("response", {}).get("results", [])
        else:
            raise Exception("Invalid response")

    def post(self, path, data=None, files=None, extra_headers=None):
        _headers = self.headers(extra_headers=extra_headers)
        data = data or {}
        try:
            _url = self.get_url(path)
            response = requests.post(_url, data=data, headers=_headers, files=files)
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_exception:
            raise APIException(http_exception)
        response_data = response.json()
        if response_data.get("response", {}).get("success"):
            return response_data["response"].get("result", response_data["response"].get("results"))
        else:
            return response_data

    def delete(self, path, data=None):
        _headers = self.headers()
        _url = self.get_url(path)
        response = requests.delete(_url, data=data, headers=_headers)
        response.raise_for_status()
        response_data = response.json()
        if response_data.get("response", {}).get("success"):
            return response_data["response"].get("result", response_data["response"].get("results"))
        else:
            return response_data

    def authenticate(
        self, email, password, user_agent=None, ip_address=None, code=None, case_id=None
    ):
        _headers = {
            "X-Origin-Environment": ENVIRONMENT_KEY,
        }
        if user_agent:
            _headers["X-User-Agent"] = user_agent
        if ip_address:
            _headers["X-Forwarded-For"] = ip_address
        response = requests.post(
            self.get_url("/auth"),
            data={
                "email": email,
                "password": password,
                "code": code,
                "case_id": case_id,
            },
            headers=_headers,
        )
        response.raise_for_status()
        response_data = response.json()
        return response_data.get("response")

    def register(self, email, password, name):
        response = requests.post(
            self.get_url("/register/"),
            data={
                "email": email,
                "password": password,
                "name": name,
            },
            headers={"X-Origin-Environment": ENVIRONMENT_KEY},
        )
        response_data = response.json()
        return response_data.get("response")

    def register_public(self, *, email, password, name, code=None, case_id=None, **kwargs):
        response = requests.post(
            self.get_url("/register/"),
            data={
                "email": email,
                "password": password,
                "name": name,
                "code": code,
                "case_id": case_id,
                "phone": kwargs.get("phone"),
                "country": kwargs.get("country"),
                "organisation_name": kwargs.get("organisation_name"),
                "organisation_id": kwargs.get("organisation_id"),
                "organisation_country": kwargs.get("organisation_country"),
                "companies_house_id": kwargs.get("companies_house_id"),
                "organisation_postcode": kwargs.get("organisation_postcode"),
                "organisation_address": kwargs.get("organisation_address"),
                "vat_number": kwargs.get("vat_number"),
                "eori_number": kwargs.get("eori_number"),
                "duns_number": kwargs.get("duns_number"),
                "organisation_website": kwargs.get("organisation_website"),
                "contact_address": kwargs.get("contact_address"),
                "confirm_invited_org": kwargs.get("confirm_invited_org"),
            },
            headers={"X-Origin-Environment": ENVIRONMENT_KEY},
        )
        response_data = response.json()
        return response_data.get("response")
