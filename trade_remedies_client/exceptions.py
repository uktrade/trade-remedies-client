class APIException(Exception):
    def __init__(self, *args, **kwargs):
        if args and issubclass(type(args[0]), Exception):
            try:
                self.detail = args[0].response.json()
                self.status_code = args[0].response.status_code
                self.message = self.detail.get("detail")
            except Exception as apiexc:
                self.message = "Unknown error"
        elif args:
            self.message = args[0]
        else:
            self.message = "Unknown error"
        super().__init__(self.message, **kwargs)
