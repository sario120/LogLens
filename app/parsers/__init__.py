from app.parsers.nginx_access import NginxAccessParser
from app.parsers.nginx_error import NginxErrorParser
from app.parsers.container import ContainerLogParser
from app.parsers.syslog import SyslogParser
from app.parsers.api_backend import ApiBackendParser
from app.parsers.postgres import PostgresParser

PARSERS = {
    "nginx_access": NginxAccessParser,
    "nginx_error": NginxErrorParser,
    "container": ContainerLogParser,
    "syslog": SyslogParser,
    "api_backend": ApiBackendParser,
    "postgres": PostgresParser,
}

LOG_TYPES = list(PARSERS.keys())
