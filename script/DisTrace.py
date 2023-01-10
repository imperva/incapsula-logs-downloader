import json
import pycef
from opentelemetry import trace
from opentelemetry.trace import SpanKind
from opentelemetry.semconv.trace import SpanAttributes
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator


class DisTrace:
    def __init__(self, logger):
        self.logger = logger

    def event_handler(self, event):
        w3c_fields = ["date", "time", "visit_id", "client_app", "browser_type", "js_support", "cookie_support",
                      "client_app_sig", "cap_support", "su_id", "user_agent", "session_id", "site_id", "country_code",
                      "tag", "city_code", "domain", "lat", "long", "account_name", "pop", "url", "post_body", "version",
                      "action", "external_id", "referrer", "origin_ip", "port", "method", "url_query", "status_code", "xff",
                      "bytes", "start", "port", "rule", "client_ip", "prot_ver", "end", "additional_req_headers",
                      "additional_res_headers", "severity", "attack_type", "attack_id", "rule_name", "rule_info"]

        if event is not None:
            # self.logger.debug("Original message: {}".format(event))
            cwaf_dict = self.clean_dict(pycef.parse(event),
                                   [("cs4", "visit_id"), ("cs1", "cap_support"), ("suid", "su_id"),
                                    ("requestClientApplication", "user_agent"),
                                    ("fileId", "session_id"), ("siteid", "site_id"), ("ccode", "country_code"),
                                    ("cicode", "city_code"),
                                    ("src", "client_ip"), ("app", "version"), ("deviceExternalId", "external_id"),
                                    ("additionalReqHeaders", "additional_req_headers"),
                                    ("additionalResHeaders", "additional_res_headers"), ("request", "url"),
                                    ("ref", "referrer"),
                                    ("requestMethod", "method"), ("cn1", "status_code"), ("in", "bytes"),
                                    ("Customer", "account_name"),
                                    ("sourceServiceName", "domain"), ("act", "action"), ("cpt", "client_port"),
                                    ("ver", "prot_ver"),
                                    ("deviceFacility", "pop"), ("postbody", "post_body"),
                                    ("sip", "origin_ip"), ("spt", "server_port"), ("qstr", "url_query"),
                                    ("cs2", "js_support"),
                                    ("cs3", "cookie_support"), ("cs5", "client_app_sig"),
                                    ("cs6", "client_app"), ("cs9", "rule_name"), ("fileType", "attack_type"),
                                    ("dproc", "browser_type"),
                                    ("filePermission", "attack_id"), ("cs10", "rule_info")])

            trace_parent = self.get_rules(pycef.parse(event))
            if trace_parent is not None:
                self.send_trace(cwaf_dict, trace_parent)

    @staticmethod
    def clean_dict(cwaf_dict, convert):
        try:
            for names in convert:
                if names[0] in cwaf_dict:
                    cwaf_dict[names[1]] = cwaf_dict[names[0]]
                    del cwaf_dict[names[0]]
                if "Label" in names[0]:
                    del cwaf_dict[names[0]]
        except ValueError:
            print("Failed cleaning: {} converting {}".format(cwaf_dict, convert))
        return cwaf_dict

    def get_rules(self, cwaf_dict):
        if "Rule Info" in cwaf_dict:
            rule_info = cwaf_dict["Rule Info"]

            rule_info = rule_info.replace("\\\\", "")
            rule_info = rule_info.replace("\\", "")
            rule_info = rule_info.replace('"{"', '{"')
            rule_info = rule_info.replace('}"}', '}}')

            rules = json.loads(rule_info)
            self.logger.debug("{}".format(rules))
            for rule in rules:
                if "header_name" in rule:
                    if rule["header_name"] == "traceparent":
                        self.logger.debug("traceparent {header_orig}".format(**rule))
                        return {"traceparent": "{header_orig}".format(**rule)}
            return None

    def send_trace(self, msg, trace_info):
        self.logger.debug("Sending trace for traceparent - {traceparent}".format(**trace_info))
        resource = Resource(attributes={
            SERVICE_NAME: "my-impv",
            "service.version": "4.0",
            "deployment.environment": "dev",
            "service.language.name": "cwaf",
            "transaction.type": "proxy",
            "observer.hostname": "proxy-122903"
        })
        provider = TracerProvider()
        provider.resource.create(attributes={
            SERVICE_NAME: "my-impv",
            "service.version": "4.0",
            "deployment.environment": "dev",
            "service.language.name": "cwaf",
            "transaction.type": "proxy",
            "observer.hostname": "proxy-122903"
        })

        # processor = BatchSpanProcessor(ConsoleSpanExporter())

        processor = BatchSpanProcessor(OTLPSpanExporter(endpoint="http://RUM-0876ea756e139e34.elb.us-east-2.amazonaws.com:8200/v1/traces"))
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)

        tracer = trace.get_tracer("Imperva", "5.5")

        carrier = trace_info

        ctx = TraceContextTextMapPropagator().extract(carrier=carrier)
        start = int(msg["start"]) * 1000000
        end = int(msg["end"]) * 1000000

        with tracer.start_as_current_span("{}".format(msg["url"].replace(msg["domain"], '')), kind=SpanKind.SERVER,
                                          start_time=start, context=ctx) as span:
            try:
                span.set_attribute(SpanAttributes.HTTP_METHOD, msg["method"])
                span.set_attribute("http.target", msg["url"].replace(msg["domain"], ''))
                span.set_attribute("net.host.name", msg["domain"])
                span.set_attribute("net.host.port", msg.get("server_port") or "0")
                span.set_attribute("http.scheme", msg["version"])
                span.set_attribute("http.status_code", msg.get("status_code") or "0")
                span.set_attribute("http.user_agent", msg["user_agent"])
                span.end(end)
                self.logger.debug("Sent: {}".format(span))
            except ValueError:
                self.logger.error("Creating Span: {}".format(msg))

