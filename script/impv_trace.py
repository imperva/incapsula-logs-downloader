##################################################################################################
# Information about the gRPC TLS code.                                                           #
# https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md #
# https://grpc.io/docs/guides/auth/                                                              #
##################################################################################################
import os
import pycef
import json
from opentelemetry import trace
from opentelemetry.trace import SpanKind, TraceFlags
from opentelemetry.proto.resource.v1 import resource_pb2
from opentelemetry.proto.trace.v1 import trace_pb2
from opentelemetry.proto.common.v1 import common_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2_grpc
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest, ExportTraceServiceResponse
from opentelemetry.sdk.trace.id_generator import RandomIdGenerator, IdGenerator
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator


def trace_log(file, logger):
    trace_attributes = common_pb2.KeyValueList(
        values=[
            common_pb2.KeyValue(key='device.vendor', value=common_pb2.AnyValue(string_value="Imperva")),
            common_pb2.KeyValue(key='service.version', value=common_pb2.AnyValue(string_value="1.0")),
            common_pb2.KeyValue(key='deployment.environment', value=common_pb2.AnyValue(string_value="dev")),
            common_pb2.KeyValue(key='service.name', value=common_pb2.AnyValue(string_value="WAF")),
            common_pb2.KeyValue(key='telemetry.sdk.name', value=common_pb2.AnyValue(string_value="opentelemetry")),
            common_pb2.KeyValue(key='telemetry.sdk.version', value=common_pb2.AnyValue(string_value="1.20.1"))
        ]
    )
    trace_resource = resource_pb2.Resource(attributes=trace_attributes.values)
    trace_resource_span = trace_pb2.ResourceSpans()
    trace_resource_span.schema_url = "https://opentelemetry.io/schemas/1.15.0"
    trace_resource_span.resource.CopyFrom(trace_resource)
    trace_data = trace_pb2.TracesData()
    instrumentation_scope = common_pb2.InstrumentationScope(name="imperva_cwaf", version="1.0")
    trace_scope_scan = trace_pb2.ScopeSpans(scope=instrumentation_scope)

    traces = []

    messages = remove_escape_char(file)

    for msg in messages:
        if "traceparent" in msg:
            adr = msg.split("cs10=")[1].split(" cs10Label=")[0]
            msg = msg.replace(adr, "")
            adr_json = json.loads(adr.replace("\\", ""))

            cwaf_dict = pycef.parse(msg)
            cwaf_dict = clean_dict(cwaf_dict,
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
            for item in adr_json:
                if item["header_name"] == "traceparent":
                    cwaf_dict["trace_info"] = item["header_orig"]
            traces.append(cwaf_dict)

    for waf in traces:
        span_context = trace.SpanContext(
            trace_id=int(split_trace_parent(waf)["trace_id"], 16),
            span_id=int(split_trace_parent(waf)["span_id"], 16),
            trace_flags=TraceFlags(0x01),
            is_remote=True
        )

        trace_span = trace_pb2.Span()
        trace_span.trace_id = int.to_bytes(span_context.trace_id, 16, "big")
        trace_span.span_id = int.to_bytes(RandomIdGenerator().generate_span_id(), 8, "big")
        trace_span.parent_span_id = int.to_bytes(span_context.span_id, 8, "big")
        trace_span.name = "{url}".format(**waf).replace("{domain}".format(**waf), "")
        trace_span.start_time_unix_nano = int(waf["start"]) * 1000000
        trace_span.end_time_unix_nano = int(waf["end"]) * 1000000
        trace_span.kind = SpanKind.CLIENT.value

        for item in [
            common_pb2.KeyValue(key="http.scheme",
                                value=common_pb2.AnyValue(string_value="{version}".format(**waf).lower())),
            common_pb2.KeyValue(key="http.target", value=common_pb2.AnyValue(
                string_value="{url}".format(**waf).replace("{domain}".format(**waf), ""))),
            common_pb2.KeyValue(key="http.method",
                                value=common_pb2.AnyValue(string_value="{method}".format(**waf))),
            common_pb2.KeyValue(key="net.host.name",
                                value=common_pb2.AnyValue(string_value="{domain}".format(**waf))),
            common_pb2.KeyValue(key="net.host.port", value=common_pb2.AnyValue(
                int_value=80 if "{version}".format(**waf).lower() == "http" else 443)), # int("{server_port}".format(**waf)))),
            common_pb2.KeyValue(key="http.status_code",
                                value=common_pb2.AnyValue(int_value=int("{status_code}".format(**waf)) if waf.get("status_code") else 0)),
            common_pb2.KeyValue(key="http.request_content_length",
                                value=common_pb2.AnyValue(int_value=int("{bytes}".format(**waf)) if waf.get("bytes") else 0)),
            common_pb2.KeyValue(key="http.user_agent",
                                value=common_pb2.AnyValue(string_value="{user_agent}".format(**waf)))
        ]:
            trace_span.attributes.append(item)

        trace_scope_scan.spans.append(trace_span)

    trace_resource_span.scope_spans.append(trace_scope_scan)

    trace_data.resource_spans.append(trace_resource_span)
    send_trace(trace_data, logger)
    return [True, file]


def send_trace(trace_data, logger):
    import grpc
    with grpc.insecure_channel("192.168.1.82:32111") as channel:
        stub = trace_service_pb2_grpc.TraceServiceStub(channel)
        try:
            stub.Export(trace_data)
            logger.debug("Sent: {}".format(trace_data))
        except grpc.RpcError as e:
            print("gRPC error: {}".format(e))
        except Exception as e:
            print("Error occurred: {}".format(e))


def split_trace_parent(data) -> dict:
    return {
        "trace_id": data["trace_info"].split("-")[1],
        "span_id": data["trace_info"].split("-")[2]
    }


def clean_dict(cwaf_dict, convert):
    for names in convert:
        if names[0] in cwaf_dict:
            cwaf_dict[names[1]] = cwaf_dict[names[0]]
            del cwaf_dict[names[0]]
        if "Label" in names[0]:
            del cwaf_dict[names[0]]
    return cwaf_dict


def get_rules(cwaf_dict):
    if "Rule Info" in cwaf_dict:
        rule_info = cwaf_dict["Rule Info"]

        rule_info = rule_info.replace("\\\\", "")
        rule_info = rule_info.replace("\\", "")
        rule_info = rule_info.replace('"{"', '{"')
        rule_info = rule_info.replace('}"}', '}}')

        rules = json.loads(rule_info)

        for rule in rules:
            if "header_name" in rule:
                if rule["header_name"] == "traceparent":
                    return {"traceparent": "{header_orig}".format(**rule)}
        return None


def remove_escape_char(file) -> list:
    clean_lines = []
    file_path = os.path.join("/tmp/processed/", file)
    with open(file_path, "r") as fp:
        uncompressed_file_content = fp.readlines()
        for line in uncompressed_file_content:
            line = line.replace('\\\\', '')
            # line = line.replace('\\', '')
            line = line.replace('"{"', '{"')
            line = line.replace('}"}', '}}')
            line = line.replace('[{"url"', '{"url"')
            line = line.replace('"}],', '"},')
            clean_lines.append(line)
    return clean_lines
