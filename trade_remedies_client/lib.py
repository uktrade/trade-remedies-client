import json
import logging

from cache_memoize import cache_memoize
from django.conf import settings
from requests.exceptions import HTTPError

from .exceptions import APIException

FEATURE_FLAGS_TTL = getattr(settings, "FEATURE_FLAGS_TTL", 5 * 60)
SYSTEM_PARAMS_TTL = getattr(settings, "SYSTEM_PARAMS_TTL", 5 * 60)
logger = logging.getLogger(__name__)


def all_user_cache_args_rewrite(self, *args):
    """
    An `args_rewrite` function for cache_memoize to exclude the first
    positional argument (ie the user token) from the cache key, so the cached
    value is shared by all users.
    """
    return args


def pluck(_dict, attrs):
    """
    Return a dict containing the attributes listed, plucked from the given dict.
    """
    return {key: _dict[key] for key in attrs if key in _dict}


######################################################

# GENERAL ############################################


def health_check(self):
    return self.get_one("/health/")


def get_case(self, case_id, organisation_id=None, fields=None):
    """
    Return a single full case.
    """
    if organisation_id:
        _url = f"/case/{case_id}/organisation/{organisation_id}/"
    else:
        _url = f"/case/{case_id}/"
    case = self.get_one(_url, fields=fields)
    return case


def get_cases(self, archived=False, all_cases=False, new_cases=False, fields=None):
    """
    Return all cases, archived cases or new cases.
    """
    cases = self.get_many(
        "/cases/",
        params={
            "archived": archived,
            "all_investigator": all_cases,
            "new_cases": new_cases,
            "fields": fields,
        },
    )
    return cases


def get_submissions(self, case_id, show_global=False, fields=None):
    """
    Get submissions to the case.
    If all is True, return also submissions created by TRA
    """
    path = (
        f"/case/{case_id}/submissions/global/" if show_global else f"/case/{case_id}/submissions/"
    )
    submissions = self.get_many(path, fields=fields)
    return submissions


def get_submissions(self, case_id, show_global=False, fields=None, page=1, page_size=50):
    """
    Get submissions to the case with pagination support.
    
    Args:
        case_id: The ID of the case
        show_global: If True, return also submissions created by TRA
        fields: Specific fields to return
        page: Page number (default: 1)
        page_size: Number of submissions per page (default: 50)
    
    Returns:
        list: List of submission objects for the requested page
        
    Note:
        This method uses pagination on the server side. To get all submissions,
        you may need to make multiple calls with different page numbers.
    """
    path = (
        f"/case/{case_id}/submissions/global/" if show_global else f"/case/{case_id}/submissions/"
    )
    params = {
        "page": page,
        "page_size": page_size
    }
        
    submissions = self.get_many(path, params=params, fields=fields)
    return submissions


def get_submissions_public(
    self, case_id, organisation_id=None, private=True, get_global=False, fields=None
):
    params = {
        "private": "true" if private else "false",
        "global": "true" if get_global else "false",
    }
    url = (
        f"/case/{case_id}/organisation/{organisation_id}/submissions/"
        if organisation_id
        else f"/case/{case_id}/submissions/"
    )
    submissions = self.get_many(url, params=params, fields=fields)
    return submissions


def get_submission(self, case_id, submission_id, fields=None):
    params = {"fields": fields} if fields else None
    submission = self.get_one(f"/case/{case_id}/submission/{submission_id}/", params)
    return submission


def create_submission(self, case_id, organisation_id, **kwargs):
    """
    Create a new submission record for an organisation in a case
    """
    path = (
        f"/case/{case_id}/organisation/{organisation_id}/submissions/"
        if organisation_id
        else f"/case/{case_id}/submissions/"
    )
    submission = self.post(path, data=kwargs)
    return submission


def update_submission(self, case_id, submission_id, **kwargs):
    """
    Update a submission to amend contact or name
    """
    path = f"/case/{case_id}/submission/{submission_id}/"
    data = pluck(
        kwargs,
        [
            "name",
            "contact_id",
            "organisation_id",
            "due_at",
            "time_window",
            "description",
            "url",
            "deficiency_notice_params",
        ],
    )
    submission = self.post(path, data=data)
    return submission


def set_submission_state(self, case_id, submission_id, state, issue=None):
    """
    set submission to given status
    """
    path = f"/case/{case_id}/submission/{submission_id}/status/"
    data = {"status_context": state}
    if issue is not None:
        data["issue"] = issue
    return self.post(path, data=data)


def get_submission_documents(
    self, case_id, submission_id, request_for_organisation_id=None, all_versions=None
):
    """
    Return all the documents associated with a submission. Optionally request the docs FOR a
    specific organisation (and by the requesting user)
    all_versions will get all documents for all versions of this submission
    """
    path = f"/case/{case_id}/submission/{submission_id}/documents/"
    if request_for_organisation_id:
        path = f"{path}for/{request_for_organisation_id}/"
    params = {"all_versions": all_versions}
    result = self.get_one(path, params=params)
    return result


def upload_document(
    self,
    *,
    data,
    file=None,
    organisation_id=None,
    case_id=None,
    submission_id=None,
    system=False,
    document_id=None,
    issued=False,
):
    data = data or {
        "name": "Uploaded from UI",
        "issued": issued,
    }
    files = None
    if file is not None:
        file = [file] if not isinstance(file, list) else file
        files = [("file", f) for f in file]
    if system:  # TODO: Deprecated path?
        data["system"] = True
        url = f"/documents/system/{document_id}/" if document_id else f"/documents/system/"
        document = self.post(url, data=data, files=files)
    else:
        if submission_id and organisation_id:
            path = f"/documents/case/{case_id}/organisation/{organisation_id}/submission/{submission_id}/"
        elif submission_id:
            path = f"/documents/case/{case_id}/submission/{submission_id}/"
        elif data.get("bundle_id"):
            path = f"/documents/bundle/{data['bundle_id']}/documents/"
        else:
            path = f"/documents/case/{case_id}/"
        document = self.post(path, data)
    return document


def get_documents(self, organisation_id, case_id, submission_id=None, filter_by=None):
    _url = f"/documents/case/{case_id}/organisation/{organisation_id}/submission/{submission_id}/"
    params = {}
    if filter_by:
        params["filter_by"] = filter_by
    documents = self.get_many(_url, params=params)
    return documents


def get_document(self, document_id, case_id=None, submission_id=None):
    if case_id and submission_id:
        _url = f"/documents/case/{case_id}/submission/{submission_id}/document/{document_id}/"
    else:
        _url = f"/documents/{document_id}/"
    document = self.get_one(_url)
    return document


def get_document_download_url(self, document_id, organisation_id=None, submission_id=None):
    if submission_id and organisation_id:
        _url = f"/documents/organisation/{organisation_id}/submission/{submission_id}/download/{document_id}/"
    else:
        _url = f"/documents/{document_id}/download/"
    _document = self.get_one(_url)
    return _document


def get_document_download_stream(self, document_id, submission_id=None, organisation_id=None):
    if submission_id and organisation_id:
        _url = f"/documents/organisation/{organisation_id}/submission/{submission_id}/download/{document_id}/"
    else:
        _url = f"/documents/{document_id}/download/"
    return self.get_resource(self.get_url(_url))


def get_system_parameters(self, key=None, use_cache=True, editable=False):
    """
    Return all or a single system parameters.
    If editbale is True, returns only parameters editable by an admin
    """
    url = f"/core/systemparam/"
    if key:
        values = None
        if use_cache:
            cache_key = self.md5_hash(f"SYS_PARAM_{key}")
            values = self.get_from_cache(cache_key)
        if values is None:
            values = self.get_one(url, {"key": key})
            if use_cache:
                self.set_cache(cache_key, values, SYSTEM_PARAMS_TTL)
    else:
        args = {"editable": True} if editable else None
        values = self.get_many(url, args)
    return values


def get_system_boolean(self, key, use_cache=True):
    # needed only for flags that don't have the word FEATURE at the front
    try:
        param = self.get_system_parameters(key, use_cache=use_cache)
        return param.get("raw_value")
    except Exception as exc:
        logger.warning("Unable to get system boolean: %s - %s", key, str(exc))
        return False


@cache_memoize(FEATURE_FLAGS_TTL, args_rewrite=all_user_cache_args_rewrite)
def is_feature_flag_enabled(self, key):
    url = f"/core/feature-flags/{key}/"

    try:
        is_enabled = self.get_one(url)
    except HTTPError as err:
        if err.response.status_code == 404:
            logger.warning("Feature flag not found: %s", key)
        else:
            logger.exception("Failed to get feature flag")
        is_enabled = False  # Default to False if not found.
    return is_enabled


def set_submission_status(
    self,
    case_id,
    submission_id,
    status_id,
    stage_change_if_sufficient=None,
    stage_change_if_deficient=None,
    deficiency_documents=None,
    issue=None,
):
    url = f"/case/{case_id}/submission/{submission_id}/status/"
    files = None
    if deficiency_documents:
        files = [("deficiency_documents", f) for f in deficiency_documents]
    response = self.post(
        url,
        {
            "submission_status_id": status_id,
            "stage_change_if_sufficient": stage_change_if_sufficient,
            "stage_change_if_deficient": stage_change_if_deficient,
            "issue": issue,
        },
        files=files,
    )
    return response


def get_all_case_enums(self, case_id=None, **kwargs):
    path = f"/cases/enums/{case_id}/" if case_id else "/cases/enums/"
    enums = self.get_one(path, params=kwargs)
    return enums


def set_organisation_case_role(self, case_id, organisation_id, role_key, params=None):
    """
    Set the organisation role in a case
    """
    path = f"/organisations/{organisation_id}/case/{case_id}/role/{role_key}/"
    return self.post(path, params)


def get_organisation(self, organisation_id, case_id=None):
    if case_id:
        path = f"/organisations/{organisation_id}/case/{case_id}/"
    else:
        path = f"/organisations/{organisation_id}/"
    return self.get_one(path)


def set_case_primary_contact(self, contact_id, organisation_id, case_id):
    path = f"/contacts/{contact_id}/case/{case_id}/set/primary/{organisation_id}/"
    return self.post(path)


def update_case(self, case_id, update_spec):
    response = self.post(f"/case/{case_id}/", data=update_spec)
    return response


def get_third_party_invites(self, case_id=None, submission_id=None):
    """
    Return all invites from a particular 3rd party submission
    """
    path = f"/invitations/case/{case_id}/submission/{submission_id}/"
    return self.get_many(path)


def get_user(self, user_id, organisation_id=None):
    """
    Return user info. Restrict to organisation if provided.
    """
    if organisation_id:
        path = f"/team/{organisation_id}/user/{user_id}/"
    else:
        path = f"/user/{user_id}/"
    response = self.get_one(path)
    return response


def get_user_by_email(self, user_email):
    path = f"/user/get_user_by_email/{user_email}"
    response = self.get_one(path)
    return response


def assign_user_to_case(
    self,
    user_organisation_id,
    user_id,
    case_id,
    representing_id=None,
    submission_id=None,
    primary=None,
):
    representing_str = f"representing/{representing_id}/" if representing_id else ""
    if submission_id:
        path = f"/team/{user_organisation_id}/users/assign/{user_id}/case/{case_id}/submission/{submission_id}/{representing_str}"
    else:
        path = (
            f"/team/{user_organisation_id}/users/assign/{user_id}/case/{case_id}/{representing_str}"
        )
    params = {"primary": primary}
    return self.post(path, data=params)


def two_factor_request(self, delivery_type=None, user_agent=None, ip_address=None):
    """
    Request a 2FA code
    """
    path = "/auth/2fa/"
    extra_headers = {}
    if user_agent:
        extra_headers["X-User-Agent"] = user_agent
    if ip_address:
        extra_headers["X-Forwarded-For"] = ip_address
    if delivery_type:
        path = f"{path}{delivery_type}/"
    return self.get_one(path, extra_headers=extra_headers)


def two_factor_auth(self, code, user_agent=None, ip_address=None):
    path = "/auth/2fa/"
    extra_headers = {}
    if user_agent:
        extra_headers["X-User-Agent"] = user_agent
    if ip_address:
        extra_headers["X-Forwarded-For"] = ip_address
    return self.post(path, {"2fa_code": code}, extra_headers=extra_headers)


def validate_password_reset(self, user_pk, token):
    """
    Validate (only) a password reset code.
    TODO: Uses settings.TRUSTED_USER_TOKEN
    """
    return self.get_one(
        path="/accounts/password/reset_form/", params={"token": token, "user_pk": user_pk}
    )


def request_password_reset(self, email):
    """
    request a password reset email for a given email.
    Will only be sent if the email is a valid user.
    TODO: Uses token=settings.TRUSTED_USER_TOKEN,
    """
    return self.get_one(path="/accounts/password/request_reset/", params={"email": email})


def reset_password(self, token, user_pk, password):
    """settings.TRUSTED_USER_TOKEN"""
    path = "/accounts/password/reset_form/"
    return self.post(path, {"password": password, "token": token, "user_pk": user_pk})


def organisation_user_cases(self, organisation_id):
    """
    Return unique auth details for an organisation.
    Auth details are found attached to user-case-org authentiaction objects
    """
    return self.get_many(f"/organisations/{organisation_id}/user_cases/")


def companies_house_search(self, query):
    results = self.get_many(f"/companieshouse/search/", params={"q": query})
    return results


def get_user_cases(
    self, archived=False, request_for=None, all_cases=False, outer=False, fields=None
):
    """
    Return all cases associated with this user.
    If request_for is set to a user id, the request will return case summary associated
    with the requested for user, IF the requesting user has the permission to do so
    """
    params = {"fields": fields}
    if archived:
        params["archived"] = archived if archived == "all" else "true"
    if all_cases:
        params["all"] = "true"
        params["initiated"] = "false"
    if outer:
        params["outer"] = "true"
        params["initiated"] = "false"
    if request_for:
        path = f"/cases/user/{request_for}/"
    else:
        path = "/cases/"
    cases = self.get_many(path, params=params)
    return cases


def get_invite_details(self, invite_id):
    path = f"/invitations/{invite_id}/"
    return self.get_one(path)


def get_feedback_form(self, form_key=None, form_id=None):
    try:
        if form_key:
            return self.get_one(path=f"/feedback/key/{form_key}/")
        elif form_id:
            return self.get_one(path=f"/feedback/{form_id}/")
        else:
            return None
    except HTTPError:
        return None


def get_organisation_users(self, organisation_id, case_id=None):
    """
    Return all users for this organisation or org_case
    """
    path = f"/organisations/{organisation_id}/users/"
    return self.get_many(path, {"case_id": case_id})


def available_review_types(self, case_id, is_notice=True):
    path = f"/cases/{case_id}/reviewtypes/"
    params = {}
    if is_notice:
        params["is_notice"] = True
    return self.get_many(path, params=params)


def get_notices(self, all_notices=True):
    return self.get_many(f"/cases/notices/", {"all_notices": all_notices})


def get_notice(self, notice_id):
    return self.get_one(f"/cases/notice/{notice_id}/")


# CASEWORKER PORTAL ONLY #############################


def set_case_data(self, case_id, data):
    url = f"/cases/{case_id}/"
    return self.post(url, data=data)


def delete_submission(self, case_id, submission_id):
    """
    delete submission
    """
    return self.delete(f"/case/{case_id}/submission/{submission_id}/")


def submission_notify(self, case_id, organisation_id, submission_id, values=None, notice_type=None):
    notice_type = notice_type or "invite"
    path = f"/case/{case_id}/organisation/{organisation_id}/submission/{submission_id}/notify/{notice_type}/"
    try:
        notify = self.post(path, data=values)
    except APIException as httpexc:
        notify = {"error": httpexc.detail.get("errors")}
    except Exception as exc:
        notify = {"error": str(exc)}
    return notify


def clone_submission(self, case_id, submission_id, **kwargs):
    path = f"/case/{case_id}/submission/{submission_id}/clone/"
    data = pluck(
        kwargs,
        [
            "name",
            "contact_id",
            "organisation_id",
            "due_at",
            "time_window",
            "description",
            "url",
            "deficiency_notice_params",
        ],
    )
    try:
        result = self.post(path, data=data)
    except Exception as exc:
        result = {"error": str(exc)}
    return result


def approval_notify(self, case_id, organisation_id, action, values):
    path = f"/organisations/case/{case_id}/organisation/{organisation_id}/notify/{action}/"
    self.post(path, data=values)


def approve_submission(self, submission_id):
    path = f"/organisations/submission/{submission_id}/approval/"
    self.post(path)


def verify_caserole(self, case_id, organisation_id, set=None):
    path = f"/organisations/{organisation_id}/case/{case_id}/verify/"
    self.post(path)


def reject_organisation(self, case_id, organisation_id):
    # Mark an organisation as fraudulent
    path = f"/organisations/{organisation_id}/reject/"
    self.post(path)


def invite_contact(self, case_id, contact_id, case_role_id, values):
    path = f"/invitations/invite/{contact_id}/to/{case_id}/as/{case_role_id}/"
    response = self.post(path=path, data=values)
    return response


def get_organisation_id_by_name(self, names, case_summary=False):
    """
    Return all organisation ids for a set of names
    """
    url = f"/organisations/lookup/"
    organisations = self.get_many(url, params={"name": names, "cases": case_summary})
    return organisations


def delete_organisation(self, organisation_id):
    return self.delete(f"/organisations/{organisation_id}/")


def remove_organisation_from_case(self, case_id, organisation_id):
    return self.delete(f"/organisations/{organisation_id}/case/{case_id}/remove/")


def attach_document(
    self, *, data, document_id, organisation_id=None, case_id=None, submission_id=None
):
    data = data or {"name": "Uploaded from UI"}
    data["document_id"] = document_id
    path = None
    document = None
    if case_id and organisation_id and submission_id:
        path = (
            f"/documents/case/{case_id}/organisation/{organisation_id}/submission/{submission_id}/"
        )
    elif case_id and submission_id:
        path = f"/documents/case/{case_id}/submission/{submission_id}/"
    elif "bundle_id" in data:
        bundle_id = data["bundle_id"]
        path = f"/documents/bundle/{bundle_id}/document/{document_id}/add/"
    if path:
        document = self.post(path, data)
    return document


def detach_document(self, *, document_id, case_id, submission_id):
    return self.delete(
        f"/documents/case/{case_id}/submission/{submission_id}/document/{document_id}/"
    )


def get_system_documents(self, fields=None, criteria=None):
    """
    Return all documents not part of a case or submission
    """
    params = {"fields": fields, "criteria": criteria} if fields or criteria else None
    _url = f"/documents/system/"
    documents = self.get_many(_url, params)
    return documents


def get_case_documents(
    self, case_id, source="all", order_by=None, order_dir=None, submission_id=None
):
    _url = f"/documents/case/{case_id}/{source}/"
    params = {}
    if order_by:
        params["order_by"] = order_by
        params["order_dir"] = order_dir or "asc"
    if submission_id:
        params["submission_id"] = submission_id
    documents = self.get_many(_url, params=params)
    return documents


def get_case_document_count(self, case_id):
    _url = f"/documents/case/{case_id}/count/"
    return self.get_one(_url)


def issue_documents_to_case(self, case_id, document_ids, name=None, submission_type_id=None):
    _url = f"/documents/case/{case_id}/issue/"
    response = self.post(
        _url,
        data={"name": name, "document_ids": document_ids, "submission_type_id": submission_type_id},
    )
    return response


def set_submission_document_state(
    self, case_id, submission_id, document_id, status, block_from_public_file, block_reason
):
    _url = f"/case/{case_id}/submission/{submission_id}/document/{document_id}/status/"
    params = {
        "status": status,
        "block_from_public_file": block_from_public_file,
        "block_reason": block_reason,
    }
    response = self.post(_url, data=params)
    return response


def toggle_documents_confidentiality(self, case_id, document_ids):
    _url = f"/documents/case/{case_id}/confidential/"
    response = self.post(_url, data={"document_ids": document_ids})
    return response


def set_system_parameter(self, key, value):
    url = f"/core/systemparam/"
    response = self.post(url, {"key": key, "value": value})
    cache_key = self.md5_hash(f"SYS_PARAM_{key}")
    self.set_cache(cache_key, response, SYSTEM_PARAMS_TTL)
    return response


def set_case_content(self, case_id, content_id=None, content=None):
    # Create or update content
    if content_id:
        url = f"/case/{case_id}/content/{content_id}/"
        response = self.post(url, content)
    else:
        url = f"/case/{case_id}/content/"
        response = self.post(url, content)
    return response


def get_case_content(self, case_id, content_id=None):
    if content_id:
        url = f"/case/{case_id}/content/{content_id}/"
        content = self.get_one(url)
    else:
        url = f"/case/{case_id}/content/"
        content = self.get_many(url)
    return content


def get_nav_section(self, case_id, selected_content=None, content=None):
    def _process_nav(id, sections, level=0):
        found = None
        for section in sections:
            section["level"] = level
            section["active"] = str(section.get("id")) == id
            section["open"] = section["active"]
            if section["open"]:
                found = section
            elif section.get("children"):
                res = _process_nav(id, section["children"], level + 1)
                if res is not None:
                    found = res
                    section["open"] = True
        return found

    if content is None:
        url = f"/case/{case_id}/content/"
        content = self.get_many(url)
    _process_nav(str(selected_content), content)
    return content


def get_audit(self, case_id, start=0, limit=None, milestone=None):
    url = f"/audit/case/{case_id}/"
    data = self.get_many(
        url,
        {
            "order_by": "-created_at",
            "milestone": milestone is True,
            "start": start,
            "limit": limit or 0,
        },
    )
    return data


def get_audit_export(self, case_id):
    path = f"/audit/case/{case_id}/export/"
    return self.get_resource(self.get_url(path))


def get_case_workflow(self, case_id):
    path = f"/case/{case_id}/workflow/"
    return self.get_one(path)


def save_case_workflow(self, case_id, workflow):
    path = f"/case/{case_id}/workflow/"
    return self.post(path, {"workflow": workflow})


def set_case_workflow_state(self, case_id, node_keys=None, values=None):
    """
    Assign response values to a case workflow nodes.
    :param case_id uuid: case UUID
    :param node_keys list: list of node keys
    :values values dict: a dict where keys are the node_keys and the values are responses.
    """
    if isinstance(values, dict) and not node_keys:
        node_keys = list(values.keys())
    path = f"/case/{case_id}/workflow/state/"
    payload = {"nodes": node_keys}
    payload.update(values)
    return self.post(path, payload)


def get_notes(self, case_id, content_type, model_id, model_key=None):
    def note_sort(note):
        return note["created_at"]

    if model_key:
        path = f"/note/case/{case_id}/on/{content_type}/{model_id}/{model_key}/"
    else:
        path = f"/note/case/{case_id}/on/{content_type}/{model_id}/"
    note_list = self.get_many(path)
    """for note in note_list:
        if note['note']:
            note['html'] = mark_safe(markdown.markdown(note['note']))"""
    note_list.sort(key=note_sort, reverse=False)
    return note_list


def create_note(
    self, case_id, content_type, model_id, note_text, note_data=None, document=None, model_key=None
):
    path = f"/note/case/{case_id}/on/{content_type}/{model_id}/"
    params = {
        "note": note_text,
        "model_key": model_key,
        "data": note_data,
    }
    return self.post(path, params, files={"document": document} if document else None)


def update_note(self, case_id, note_id, note_text, document=None):
    path = f"/note/case/{case_id}/{note_id}/"
    return self.post(path, {"note": note_text})


def add_note_document(self, case_id, note_id, document=None, confidentiality=None):
    path = f"/note/case/{case_id}/{note_id}/"
    return self.post(
        path,
        {
            "confidentiality": confidentiality,
            "document": document if document else None,
        },
    )


def delete_note_document(self, case_id, note_id, document_id):
    path = f"/note/case/{case_id}/{note_id}/document/{document_id}/"
    return self.delete(path)


def update_note_document(self, case_id, note_id, document_id, confidentiality):
    path = f"/note/case/{case_id}/{note_id}/document/{document_id}/"
    params = {"confidentiality": confidentiality}
    return self.post(path, params)


def submit_full_case_data(self, case_data):
    """
    Submit a full case data pack (e.g., full Ex Officio case) for creation
    """
    path = f"/cases/initiate/" if case_data.get("id") else "/cases/initiate/"
    return self.post(path, case_data)


def get_contact_case_invitations(self, case_id, contact_id=None):
    if contact_id:
        path = f"/invitations/for/{contact_id}/to/{case_id}/"
    else:
        path = f"/invitations/to/{case_id}/"
    return self.get_many(path)


def lookup_contacts(self, term):
    return self.get_many(f"/contacts/lookup/", {"term": term})


def get_case_team_members(self, case_id):
    """
    return all team members for a case
    """
    path = f"/case/{case_id}/team/"
    return self.get_many(path)


def assign_case_team(self, case_id, user_ids):
    """
    Assign a full team to the case, replacing whichever team might already
    be assigned.
    """
    path = f"/case/{case_id}/users/assign/"
    params = {"user_id": user_ids}
    return self.post(path, data=params)


def get_case_roles(self, exclude=None):
    path = f"/security/roles/"
    return self.get_many(path, params={"exclude": exclude})


def get_case_role(self, role_id):
    path = f"/security/role/{role_id}/"
    return self.get_one(path)


def get_organisation_case_role(self, case_id, organisation_id, fields=None):
    """
    Get the organisation role in a case
    """
    path = f"/organisations/case/{case_id}/organisation/{organisation_id}/"
    return self.get_one(path, fields=None)


def set_organisation_case_role_loa(self, case_id, organisation_id, params):
    """
    Set letter of authority details
    """
    path = f"/organisations/case/{case_id}/organisation/{organisation_id}/loa/"
    return self.post(path, params)


def get_organisations(self, case_id=None, gov_body=None, fields=None):
    if case_id:
        path = f"/organisations/case/{case_id}/"
    else:
        path = f"/organisations/"
    params = {"fields": fields}
    if gov_body:
        params["gov_body"] = True
    return self.get_many(path, params)


def update_organisation(self, organisation_id, organisation_params):
    """
    Update an organisation record.
    """
    path = f"/organisations/{organisation_id}/"
    return self.post(path, data=organisation_params)


def update_case_organisation_by_type(self, case_id, organisation_type, organisation_params):
    path = f"/organisations/case/{case_id}/{organisation_type}/organisation/"
    return self.post(path, data=organisation_params)


def get_organisation_contacts(self, organisation_id, case_id, exclude_indirect=None):
    path = f"/organisations/{organisation_id}/contacts/"
    params = {"case_id": case_id}
    if exclude_indirect:
        params["exclude_indirect"] = exclude_indirect
    return self.get_many(path, params)


def get_all_users(self, groups=None, group_name=None):
    path = f"/users/{group_name}" if group_name else "/users/"
    params = {"groups": groups} if groups else {}
    return self.get_many(path, params=params)


def get_contact(self, contact_id):
    path = f"/contact/{contact_id}/"
    return self.get_one(path)


def update_contact(self, contact_id, contact_params):
    """
    Update an existing contact
    """
    path = f"/contact/{contact_id}/"
    return self.post(path, data=contact_params)


def create_and_add_contact(self, case_id, organisation_id, contact_params):
    """
    Create a contact and add it to a case
    """
    path = f"/contacts/case/{case_id}/organisation/{organisation_id}/contact/add/"
    return self.post(path, data=contact_params)


def get_notification_template(self, template_id):
    path = f"/core/notification/template/{template_id}/"
    return self.get_one(path)


def create_contact(self, params):
    response = self.post("/contacts/", data=params)
    return response


def delete_contact(self, contact_id):
    response = self.delete(f"/contact/{contact_id}/")
    return response


def get_case_submission_bundles(self, case_id=None, bundle_id=None, status=None):
    path = f"/documents/case/{case_id}/bundles/"
    if bundle_id:
        return self.get_one(path, params={"bundle_id": bundle_id})
    return self.get_many(
        path,
        params={
            "case_id": case_id,
            "status": status,
        },
    )


def set_case_submission_bundle(self, bundle_id=None, data=None):
    response = self.post(
        f"/documents/bundle/{bundle_id}/" if bundle_id else f"/documents/bundle/", data=data
    )
    return response


def delete_case_submission_bundle(self, case_id, case_document_id):
    response = self.delete(
        f"/case/{case_id}/documents/", params={"case_document_id": case_document_id}
    )
    return response


def get_case_users(self, case_id):
    response = self.get_many(f"/case/{case_id}/users/")
    return response


def get_duplicate_organisations(self, limit=None):
    params = {"limit": limit}
    response = self.get_many("/organisations/dedupe/", params=params)
    return response


def get_case_invite_submissions(self, case_id):
    """
    Return all 3rd party invite submissions a case
    """
    path = f"/cases/{case_id}/invites/"
    return self.get_many(path)


def action_third_party_invite(self, case_id, submission_id, contact_id, params):
    path = f"/invitations/case/{case_id}/submission/{submission_id}/invite/contact/{contact_id}/notify/"
    return self.post(path, data=params)


def create_or_update_user(self, data, user_id=None):
    """
    User create or update (used from caseworker)
    """
    path = f"/user/{user_id or 'create'}/"
    return self.post(path, data=data)


def delete_user(self, user_id):
    path = f"/user/{user_id}/"
    return self.delete(path)


def get_my_account(self):
    """
    Return user info
    """
    path = "/my-account/"
    response = self.get_one(path)
    return response


def update_my_account(self, data):
    """
    Return user info
    """
    path = "/my-account/"
    response = self.post(path, data=data)
    return response


def get_all_job_titles(self):
    path = "/core/jobtitles/"
    return self.get_many(path)


def get_document_bundles(self, case_type_id=None, status=None):
    path = "/documents/bundles/"
    if case_type_id:
        path = f"{path}for/{case_type_id}/"
    if status:
        path = f"{path}status/{status}/"
    return self.get_many(path=path)


def get_document_bundle(self, bundle_id):
    path = f"/documents/bundle/{bundle_id}/"
    return self.get_one(path)


def create_document_bundle(self, case_type_id=None, submission_type_id=None):
    if case_type_id:
        path = f"/documents/bundles/for/{case_type_id}/"
    else:
        path = f"/documents/bundles/for/subtype/{submission_type_id}/"
    return self.post(path)


def update_document_bundle(self, bundle_id, data):
    path = f"/documents/bundle/{bundle_id}/"
    return self.post(path, data=data)


def delete_application_bundle(self, bundle_id):
    path = f"/documents/bundle/{bundle_id}/"
    return self.delete(path)


def remove_bundle_document(self, bundle_id, document_id):
    path = f"/documents/bundle/{bundle_id}/document/{document_id}/remove/"
    return self.delete(path)


@cache_memoize(FEATURE_FLAGS_TTL, args_rewrite=all_user_cache_args_rewrite)
def get_base_notify_context(self):
    return {
        "footer": self.get_system_parameters("NOTIFY_BLOCK_FOOTER")["value"],
        "email": self.get_system_parameters("TRADE_REMEDIES_EMAIL")["value"],
        "guidance_url": self.get_system_parameters("LINK_HELP_BOX_GUIDANCE")["value"],
    }


def create_notify_context(self, extra_context=None):
    context = get_base_notify_context(self)

    if extra_context:
        context.update(extra_context)

    return context


def organisation_cases(self, organisation_id):
    """
    Return all cases related to an organisation
    """
    cases = self.get_many(f"/cases/organisation/{organisation_id}/all/")
    return cases


def get_organisation_matches(self, organisation_id=None, **kwargs):
    """
    Reurn a match structure for one organisation - containing potential duplicates an lots of other information
    """
    if organisation_id:
        path = f"/organisations/{organisation_id}/matches/"
    else:
        path = f"/organisations/matches/"

    matches = self.get_one(path, kwargs)
    return matches


def get_invitations(self, case_id, submission_id=None):
    path = f"/invitations/case/{case_id}/"
    if submission_id:
        path = f"{path}submission/{submission_id}/"
    return self.get_many(path)


def get_security_groups(self, user_type):
    """
    Return security groups by user type
    """
    groups = self.get_many(f"/security/groups/{user_type}/")
    return groups


def get_case_participants(self, case_id, fields=None):
    """
    Return all the participant patrties in a case
    """
    path = f"/case/{case_id}/participants/"
    return self.get_many(path, {"fields": fields})


def get_feedback_forms(self):
    try:
        return self.get_many(path=f"/feedback/")
    except HTTPError:
        return None


def get_feedback_collections(self, form_id):
    try:
        return self.get_many(path=f"/feedback/submit/{form_id}/")
    except HTTPError:
        return None


def export_feedback(self, form_id):
    path = f"/core/feedback/export/{form_id}/"
    return self.get_resource(self.get_url(path))


def toggle_user_admin(self, user_id, organisation_id):
    path = f"/organisations/{organisation_id}/user/{user_id}/set/admin/"
    return self.post(path)


def toggle_organisation_sampled(self, organisation_id, case_id):
    """
    Toggle the organisation's sampled flag for a case
    """
    path = f"/organisations/{organisation_id}/case/{case_id}/sampled/"
    return self.post(path)


def toggle_organisation_nonresponsive(self, organisation_id, case_id):
    """
    Toggle the organisation's non responsive flag for a case
    """
    path = f"/organisations/{organisation_id}/case/{case_id}/nonresponsive/"
    return self.post(path)


def organisation_merge(self, organisation_id, merge_with, params):
    """
    Merge one organisation with another
    """
    path = f"/organisations/{organisation_id}/"
    return self.post(path, {"merge_with": merge_with, "parameter_map": params})


def case_milestones(self, case_id):
    path = f"/cases/{case_id}/milestones"
    return self.get_many(path)


def set_case_milestone(self, case_id, milestone_key, date):
    path = f"/cases/{case_id}/milestone/{milestone_key}/"
    return self.post(path, {"date": date})


def create_update_notice(
    self,
    name,
    reference,
    terminated_at=None,
    published_at=None,
    notice_id=None,
    case_type=None,
    review_case=None,
):
    path = f"/cases/notice/{notice_id}/" if notice_id else "/cases/notice/"
    return self.post(
        path,
        {
            "name": name,
            "reference": reference,
            "terminated_at": terminated_at,
            "published_at": published_at,
            "review_case_id": review_case,
            "case_type_id": case_type,
        },
    )


def search_documents(
    self,
    case_id=None,
    query=None,
    confidential_status=None,
    user_type=None,
    organisation_id=None,
    **kwargs,
):
    path = f"/documents/search/"
    if case_id:
        path = f"{path}case/{case_id}/"
    _url = self.get_url(path)
    params = {
        "q": query,
        "confidential_status": confidential_status,
        "user_type": user_type,
        "organisation_id": organisation_id,
    }
    response = self.get(_url, params=params)
    return response.get("response", {})


def get_tasks(self, query=None, fields=None):
    params = {
        "query": query,
        "fields": fields,
    }
    return self.get_many(f"/tasks/", params=params)


def create_update_task(self, task_id=None, content_type=None, model_id=None, data=None):
    path = f"/tasks/{task_id}/" if task_id else "/tasks/"
    # if content_type:
    #    path += f'on/{content_type}/{model_id}/'
    return self.post(path, data)


def delete_task(self, task_id):
    return self.delete(f"/tasks/{task_id}/")


# PUBLIC PORTAL ONLY #################################


def get_application_state(self, organisation_id, case_id):
    """
    Return the state structure of a case
    """
    if organisation_id and case_id:
        state = self.get_one(f"/case/{case_id}/organisation/{organisation_id}/state/")
    else:
        state = self.get_one(f"/case/state/")
    return state


def get_submission_public(self, case_id, submission_id, organisation_id=None, private=True):
    params = {"private": "true" if private else "false"}
    if organisation_id:
        path = f"/case/{case_id}/organisation/{organisation_id}/submission/{submission_id}/"
    else:
        path = f"/case/{case_id}/submission/{submission_id}/"
    submission = self.get_one(path, params=params)
    return submission


def update_submission_public(self, case_id, organisation_id, submission_id, data, **kwargs):
    path = f"/case/{case_id}/organisation/{organisation_id}/submission/{submission_id}/"
    return self.post(path, data=data)


def submission_type_exists_for_case(self, case_id, organisation_id, submission_type_id):
    return self.get_one(
        f"/case/{case_id}/organisation/{organisation_id}/submission/type/{submission_type_id}/"
    )


def get_organisation_cases(self, organisation_id, initiated_only=True, all_cases=None, outer=None):
    """
    Return all cases for an organisation
    """
    url = f"/cases/organisation/{organisation_id}/" if organisation_id else "/cases/"
    params = {}
    if initiated_only is not None:
        params["initiated"] = initiated_only
    if all_cases is not None:
        params["all"] = all_cases
    if outer is not None:
        params["outer"] = outer
    cases = self.get_many(url, params)
    return cases


def remove_document(self, organisation_id, case_id, submission_id, document_id):
    _url = f"/documents/case/{case_id}/organisation/{organisation_id}/submission/{submission_id}/delete/{document_id}/"
    response = self.delete(_url)
    return response


def get_product(self, organisation_id, case_id, product_id=None):
    _url = f"/case/{case_id}/organisation/{organisation_id}/product/"
    product = self.get_one(_url)
    return product


def submit_product_information(
    self,
    organisation_id,
    case_id,
    sector_id,
    description,
    product_id=None,
    name=None,
    hs_codes=None,
):
    if product_id:
        url = f"/cases/{case_id}/organisation/{organisation_id}/product/{product_id}/"
    else:
        url = f"/cases/{case_id}/organisation/{organisation_id}/product/"
    _product = self.post(
        url,
        data={
            "sector_id": sector_id,
            "description": description,
            "product_name": name,
            "hs_codes": hs_codes,
        },
    )
    return _product


def remove_product_hs_code(self, organisation_id, case_id, product_id, code_id):
    _url = f"/cases/{case_id}/organisation/{organisation_id}/product/{product_id}/hscode/{code_id}/"
    return self.delete(_url)


def get_source_of_exports(self, organisation_id, case_id, export_source_id=None):
    _url = f"/case/{case_id}/organisation/{organisation_id}/exportsource/"
    return self.get_many(_url)


def submit_source_of_exports(
    self, organisation_id, case_id, country, num_of_companies, export_source_id=None
):
    if export_source_id:
        url = f"/cases/{case_id}/organisation/{organisation_id}/exportsource/{export_source_id}/"
    else:
        url = f"/cases/{case_id}/organisation/{organisation_id}/exportsource/"
    _source = self.post(url, data={"country": country, "num_of_companies": num_of_companies})
    return _source


def submit_source_of_exports_public(
    self, organisation_id, case_id, sources, evidence_of_subsidy=None
):
    url = f"/cases/{case_id}/organisation/{organisation_id}/exportsource/"
    _source = self.post(
        url,
        data={
            "sources": json.dumps(sources),
            "evidence_of_subsidy": evidence_of_subsidy,
        },
    )
    return _source


def set_review_flag(self, organisation_id, case_id, submission_id, review=None):
    url = f"/cases/{case_id}/organisation/{organisation_id}/submission/{submission_id}/review/"
    submission = self.post(url, data={"review": review})
    return submission


def set_review_type(self, case_id, submission_id, reference_case, review_type):
    url = f"/cases/{case_id}/submission/{submission_id}/reviewtype/"
    self.post(
        url,
        data={
            "reference_case": reference_case,
            "case_type": review_type,
        },
    )


def set_submission_status_public(self, case_id, submission_id, status_id=None, status_context=None):
    url = f"/case/{case_id}/submission/{submission_id}/status/"
    response = self.post(
        url,
        {
            "submission_status_id": status_id,
            "status_context": status_context,
        },
    )
    return response


def get_organisation_invite_submissions(self, organisation_id):
    """
    Return 3rd party invite submissions for an organisation
    """
    path = f"/cases/organisation/{organisation_id}/invites/"
    return self.get_many(path)


def remove_third_party_invite(self, case_id, submission_id, invite_id):
    """
    Remove an invitee from a 3rd party invitation submission
    """
    path = f"/invitations/case/{case_id}/submission/{submission_id}/remove/{invite_id}"
    return self.delete(path)


def get_team_users(self):
    """
    Used from Public to return all users for the requestor's team (same organisation)
    """
    path = f"/team/users/"
    response = self.get_many(path)
    return response


def update_create_team_user(self, organisation_id, data, user_id=None):
    """
    Create or update an organisation user
    """
    path = f"/team/{organisation_id}/user/"
    if user_id:
        path = f"{path}{user_id}/"
    response = self.post(path, data=data)
    return response


def get_pending_user_case_assignments(self, organisation_id, user_id=None):
    path = f"/team/{organisation_id}/users/assign/"
    return self.get_many(path)


def remove_user_from_case(self, organisation_id, user_id, case_id, representing_id):
    path = f"/team/{organisation_id}/users/assign/{user_id}/case/{case_id}/representing/{representing_id}/"
    return self.post(
        path,
        data={
            "remove": True,
        },
    )


def get_latest_notices(self, limit=None):
    path = "/cases/publicnotices/"
    params = {"limit": limit} if limit else None
    return self.get_many(path, params=params)


def get_public_case_record(self, case_number):
    path = f"/case/{case_number}/public/"
    return self.get_one(path)


def get_case_state(self, case_ids, fields):
    if len(case_ids) == 1:
        path = f"/case/{case_ids[0]}/state/"
    else:
        path = f"/case/state/"
    params = {"fields": fields, "cases": case_ids}
    return self.get_one(path, params=params)


# TODO : Check this without user
def get_all_cases(self, param="all", exclude_types=None):
    """
    Return all cases. If a user is not provided, the public case list is returned
    """
    url = f"/cases/"
    params = {param: "true"}
    if exclude_types:
        params["exclude_types"] = exclude_types
    cases = self.get_many(url, params=params)
    return cases


# TODO check this without user
def get_case_counts(self, params=None):
    """
    Return all cases. If a user is not provided, the public case list is returned
    """
    url = f"/cases/count/"
    cases = self.get_one(url, params=params)
    return cases


def initiate_new_application(self, organisation_id=None, **kwargs):
    kwargs["representing"] = kwargs.get("representing") or "own"
    result = self.post("/case/initiate/", data={"organisation_id": organisation_id, **kwargs})
    organisation = result["organisation"]
    case = result["case"]
    submission = result["submission"]
    return organisation, case, submission


def submit_organisation_information(self, case_id=None, **kwargs):
    _url = f"/case/{case_id}/organisation/"
    _organisation = self.post(_url, data=kwargs)
    return _organisation


def get_case_invitation_by_code(self, code, case_id):
    path = f"/invitations/details/{code}/{case_id}/"
    return self.get_one(path)


def remove_submission(self, case_id, organisation_id, submission_id, **kwargs):
    path = f"/case/{case_id}/organisation/{organisation_id}/submission/{submission_id}/"
    return self.delete(path)


def register_interest_in_case(self, case_id, submission_id=None, **kwargs):
    """
    Register an interest in a case
    """
    path = f"/case/interest/{case_id}/"
    params = {"submission_id": submission_id, **kwargs}
    response = self.post(path, data=params)
    return response


def get_registration_of_interest(self, all_interests=False):
    path = "/case/interest/"
    params = {"preparing": "true"}
    if all_interests:
        params["all"] = "true"
    response = self.get_many(path, params=params)
    return response


def get_public_security_groups(self):
    """
    Return all public security groups
    """
    groups = self.get_many("/security/groups/public/")
    return groups


def get_user_case_organisations(self, case_id):
    """
    Return all the organisations this user is associated with for this case
    """
    path = f"/case/{case_id}/organisations/"
    return self.get_many(path)


def get_submission_type(self, submission_type_id):
    path = f"/cases/submission_type/{submission_type_id}/"
    sub_type = self.get_one(path)
    return sub_type


def is_representing(self, organisation_id):
    """
    Check if this user is representing a given organisation
    """
    path = f"/security/representing/{organisation_id}/"
    return self.post(path)


def get_user_invitations(self):
    """
    Return all invitations made by a user
    """
    path = "/invitations/users/"
    return self.get_many(path)


def third_party_invite(self, case_id, organisation_id, submission_id=None, invite_params=None):
    """
    Create or update a 3rd party invite
    """
    if submission_id:
        path = f"/invitations/invite/case/{case_id}/organisation/{organisation_id}/submission/{submission_id}/"
    else:
        path = f"/invitations/invite/case/{case_id}/organisation/{organisation_id}/"
    return self.post(path, data=invite_params)


def submit_feedback(self, form_key, placement_id, data):
    path = f"/feedback/submit/{form_key}/placement/{placement_id}/"
    return self.post(path, data)


def verify_email(self, code=None):
    """
    Verify email using the code or resend the verification email if not provided
    TODO: Optionally uses trusted token
    """
    if code:
        # Trusted token should be used here
        path = f"/auth/email/verify/{code}/"
    else:
        path = f"/auth/email/verify/"
    return self.post(path)


def validate_user_invitation(self, code, organisation_id):
    """
    Validate an organisation user invitation
    """
    path = f"/invitations/validate/{code}/{organisation_id}/"
    return self.get_one(path)


def create_and_invite_user(self, organisation_id, data, invitation_id=None):
    """
    Create a pending user record and send the user an invite to complete the registration
    """
    if invitation_id:
        path = f"/user/organisation/{organisation_id}/update/pending/{invitation_id}/"
    else:
        path = f"/user/organisation/{organisation_id}/create/pending/"
    return self.post(path, data=data)


def complete_user_registration(self, invitation_id, organisation_id, params=None):
    path = f"/team/{organisation_id}/user/invite/{invitation_id}/"
    return self.post(path, data=params)


def delete_pending_invite(self, invitation_id, organisation_id):
    path = f"/user/organisation/{organisation_id}/delete/pending/{invitation_id}/"
    return self.delete(path)


def get_trusted_invitation_details(self, case_id, code):
    """
    Invitation screen contain the case details. At this point there is not yet a user
    to request them. We will be using the health check user as a trusted accessing party
    to retrieve limited subsets of the case data.
    TODO: Uses trusted token
    """
    path = f"/invitations/details/{code}/{case_id}/"
    return self.get_one(path)


def get_sectors(self):
    """
    Return all available industry sectors
    """
    return self.get_many("/sectors/")


def v2_register(self, registration_data):
    # V2 registration helper
    return self.post("/v2_register/", data=registration_data)


def send_email_verification_link(self, user_pk):
    """Sends an email verification email to the user with PK user_pk"""
    return self.post(f"/email_verify/{user_pk}/")


def verify_email_verification_link(self, user_pk, email_verify_code):
    """Verifies that an email verification link is valid and updates the user accordingly."""
    return self.post(f"/email_verify/{user_pk}/{email_verify_code}")


def get_validation_error(self, key):
    """Gets the validation error entry for a particular key,
    found in api/core/validation_errors.py.
    """
    return self.get_one(f"/core/validation_error/{key}")


def v2_get_all_cases(self, params=None):
    return self.get_many("/v2_cases/", params=params)


def v2_get_case(self, case_id):
    return self.get_one(f"/v2_cases/{case_id}")


def v2_get_all_feature_flags(self):
    return self.get_many("/core/django-feature-flags")


def v2_get_one_feature_flag(self, feature_flag_name):
    return self.get_one(f"/core/django-feature-flags/{feature_flag_name}/")


def v2_is_user_feature_flag_activated(self, user_pk, feature_flag_name):
    return self.get_one(f"/core/users/{user_pk}/{feature_flag_name}/")


def v2_change_user_group(self, user_pk, group_name, request_method):
    return self.post(
        f"/core/v2/{user_pk}/change_group/",
        data={"group_name": group_name},
        request_type=request_method,
    )
