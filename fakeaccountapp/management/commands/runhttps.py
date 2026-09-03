import ssl

from django.conf import settings
from django.core.management.base import BaseCommand
from django.core.servers.basehttp import ThreadedWSGIServer, WSGIRequestHandler, get_internal_wsgi_application

from fakeaccountapp.network import get_private_ip_addresses


class SecureThreadedWSGIServer(ThreadedWSGIServer):
    def __init__(self, server_address, request_handler, ssl_context):
        self.ssl_context = ssl_context
        super().__init__(server_address, request_handler)

    def process_request_thread(self, request, client_address):
        try:
            ssl_request = self.ssl_context.wrap_socket(request, server_side=True)
        except ssl.SSLError:
            request.close()
            return

        try:
            self.finish_request(ssl_request, client_address)
        except Exception:
            self.handle_error(ssl_request, client_address)
        finally:
            self.shutdown_request(ssl_request)


class Command(BaseCommand):
    help = "Run the Django development server over HTTPS using ssl.SSLContext."

    def add_arguments(self, parser):
        parser.add_argument("addrport", nargs="?", default="0.0.0.0:8000")
        parser.add_argument("--certificate", default=str(settings.BASE_DIR / "certs" / "cert.pem"))
        parser.add_argument("--key", default=str(settings.BASE_DIR / "certs" / "key.pem"))

    def handle(self, *args, **options):
        host, port = self._parse_addrport(options["addrport"])
        app = get_internal_wsgi_application()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(options["certificate"], options["key"])

        httpd = SecureThreadedWSGIServer((host, port), WSGIRequestHandler, context)
        httpd.set_app(app)
        httpd.daemon_threads = True

        self.stdout.write(self.style.SUCCESS(f"Starting HTTPS development server at https://{host}:{port}/"))
        for address in get_private_ip_addresses():
            self.stdout.write(self.style.SUCCESS(f"LAN URL: https://{address}:{port}/"))
        self.stdout.write(f"Using SSL certificate: {options['certificate']}")
        self.stdout.write(f"Using SSL key: {options['key']}")
        self.stdout.write("Quit the server with CTRL-BREAK.")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            self.stdout.write("\nServer stopped.")

    def _parse_addrport(self, addrport):
        if ":" in addrport:
            host, port = addrport.rsplit(":", 1)
        else:
            host, port = "127.0.0.1", addrport

        return host, int(port)
