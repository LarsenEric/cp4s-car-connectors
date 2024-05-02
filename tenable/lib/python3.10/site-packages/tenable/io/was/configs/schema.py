'''
WASv2 Config API Endpoints Schemas
'''
from typing import Dict
from marshmallow import Schema, fields, post_dump, validate as v
from tenable.base.schema.fields import LowerCase
from tenable.base.utils.envelope import envelope


class ScopeSchema(Schema):
    option = fields.Str(validate=v.OneOf(['all', 'paths', 'urls']))
    urls = fields.List(fields.Url())
    exclude_file_extensions = fields.List(fields.Str())
    exclude_path_patterns = fields.List(fields.Str())
    dom_depth_limit = fields.Int(default=5)
    directory_depth_limit = fields.Int(default=25)
    page_limit = fields.Int(default=10000)
    decompose_paths = fields.Bool(default=False)
    exclude_binaries = fields.Bool()
    auto_redundant_paths = fields.Int(default=3)
    openapi_file = fields.Str()
    openapi_filename = fields.Str()
    crawl_script = fields.Dict()
    crawl_script_filename = field.Str()


class RateLimiterSchema(Schema):
    requests_per_second = fields.Int(default=25)
    autothrottle = fields.Bool(default=True)
    timeout_threshold = fields.Int(default=100)


class PluginSchema(Schema):
    rateLimiter = fields.Nested(RateLimiterSchema)
    mode = fields.Str()
    ids = fields.List(fields.Int())
    names = fields.List(fields.Str())
    families = fields.List(fields.Str())


class BrowserSchema(Schema):
    screen_width = fields.Int(default=1600)
    screen_height = fields.Int(default=1200)
    ignore_images = fields.Bool(default=True)
    job_timeout = fields.Int(default=10000)
    analysis = fields.Bool(default=True)
    pool_size = fields.Int()


class HTTPSchema(Schema):
    response_max_size = fields.Int(default=500000)
    request_redirect_limit = fields.Int(default=1)
    user_agent = fields.Str(default='Nessus WAS/%v')
    custom_user_agent = fields.Bool(default=True)
    request_headers = fields.Dict(keys=fields.Str(), values=fields.Str())
    request_concurrency = fields.Int(default=10)
    request_timeout = fields.Int(default=5000)


class ChromeScriptSchema(Schema):
    finish_wait = fields.Int(default=5000)
    page_load_wait = fields.Int(default=10000)
    command_wait = fields.Int(default=500)


class ElementSelector(Schema):
    element_type = fields.Str(required=True, default='dom_element')
    selector_type = fields.Str(required=True,
                               validator=v.OneOf(['text', 'attribute']))
    selector_text = fields.Str()
    selector_obj = fields.Dict(keys=fields.Str(), values=fields.Str())

    @pre_load(many=False)
    def deserialize_selector(self, data, **kwargs):
        sel_type = data.get('selector_type')
        if sel_type == 'text':
            data['selector_text'] = data.pop('selector', None)
        elif sel_type  == 'attribute':
            data['selector_obj'] = data.pop('selector', None)
        return data

    @post_dump(many=False)
    def serialize_selector(self, data, **kwargs):
        sel_type = data.get('selector_type')
        if sel_type == 'text':
            data['selector'] = data.pop('selector_text', None)
        if sel_type == 'attribute':
            data['selector'] = data.pop('selector_obj', None)
        return data


class AssessmentSchema(Schema):
    rfi_remote_url = fields.Url(default='http://rfi.nessus.org/rfi.txt')
    dictionary = fields.Str(default='limited', validator=v.OneOf(['full',
                                                                  'limited'
                                                                  ]))
    fingerprinting = fields.Bool(default=True)
    enable = fields.Bool()
    element_exclusions = fields.Nested(ElementSelector)


class AuditSchema(Schema):
    forms = fields.Bool()
    cookies = fields.Bool()
    ui_forms = fields.Bool()
    ui_inputs = fields.Bool()
    headers = fields.Bool()
    links = fields.Bool()
    parameter_names = fields.Bool()
    parameter_values = fields.Bool()
    jsons = fields.Bool()
    xmls = fields.Bool()
    cookies_extensively = fields.Bool()
    with_raw_payloads = fields.Bool()
    with_both_http_methods = fields.Bool()
    with_extra_parameter = fields.Bool()


class CredentialsSchema(Schema):
    credential_ids = fields.List(fields.UUID())


class SettingsSchema(Schema):
    description = fields.Str()
    timeout = fields.Str()
    debug_mode = fields.Bool()
    input_force = fields.Bool()
    credentials = fields.Nested(CredentialsSchema)
    scope = fields.Nested(ScopeSchema)
    plugin = fields.Nested(PluginSchema)
    browser = fields.Nested(BrowserSchema)
    http = fields.Nested(HTTPSchema)
    chrome_script = fields.Nested(ChromeScriptSchema)
    assessment = fields.Nested(AssessmentSchema)
    audit = fields.Nested(AuditSchema)


class ScheduleSchema(Schema):
    rrule = fields.Str()
    starttime = fields.DateTime(format='%Y%m%dT%H%M%S')
    timezone = fields.Str(default='UTC')
    enabled = fields.Bool()


class NotificationsSchema(Schema):
    emails = fields.List(fields.Str())


class PermissionSchema(Schema):
    entity = fields.Str(retuired=True, validator=v.OneOf(['user', 'group']))
    entity_id = fields.UUID(retuired=True)
    level = fields.Str(retuired=True, validator=v.OneOf(['no_access',
                                                         'view',
                                                         'control',
                                                         'configure'
                                                         ]))
    permissions_id = fields.UUID(required=True)


class ConfigSchema(Schema):
    name = fields.Str()
    targets = fields.List(fields.Url())
    description = fields.Str()
    folder_id = fields.Int()
    owner_id = fields.UUID()
    template_id = fields.UUID()
    user_template_id = fields.UUID()
    scanner_id = fields.Int()
    schedule = fields.Nested(ScheduleSchema)
    notifications = fields.Nested(NotificationsSchema)
    permissions = fields.List(fields.Nested(PermissionSchema))
    settings = fields.Nested(SettingsSchema)
