"""
Simple HTTP Trigger

DO NOT USE IN PRODUCTION

Exposes a web server (default port 9000), passes 
values passed via the querystring to the dispatcher.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from .base_trigger import BaseTrigger
from ..dispatchers import CommandLineDispatcher
from ..exceptions import ToxicCombinationError
import warnings


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def extract_query_string(self, path):
        return parse_qs(path[2:])

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Okay!")
        self.event_handler(self.extract_query_string(self.path))


class SimpleHTTPTrigger(BaseTrigger):
    """
    Simple HTTP Trigger

    DO NOT USE IN PRODUCTION

    Listens on the specified port, passes the values in the query
    string into a pipeline.
    """

    def __init__(self, *args, **kwargs):
        warnings.warn("SimpleHTTPTrigger is not safe for production systems.")
        super().__init__(*args, **kwargs)
        self.port = kwargs.get('port', 9000)

        if isinstance(kwargs['dispatcher'], CommandLineDispatcher):
            raise ToxicCombinationError('HTTP Trigger and CommandLine Dispatcher actively forbidden')

    def engage(self):
        handler = SimpleHTTPRequestHandler
        httpd = HTTPServer(("localhost", self.port), handler)
        handler.event_handler = self.on_event
        httpd.serve_forever()

if __name__ == "__main__":
    s = SimpleHTTPTrigger()
    s.engage(None)
