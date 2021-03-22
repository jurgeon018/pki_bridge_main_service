from django.core.mail.backends.smtp import EmailBackend
from pki_bridge.conf import db_settings


class ConfiguredEmailBackend(EmailBackend):
    def __init__(self, host=None, port=None, username=None, password=None,
                 use_tls=None, fail_silently=None, use_ssl=None, timeout=None,
                 ssl_keyfile=None, ssl_certfile=None,
                 **kwargs):
        super().__init__(
            host=db_settings.email_host if host is None else host,
            port=db_settings.email_port if port is None else port,
            username=db_settings.email_host_user if username is None else username,
            password=db_settings.email_host_password if password is None else password,
            use_tls=db_settings.email_use_tls if use_tls is None else use_tls,
            fail_silently=db_settings.fail_silently if fail_silently is None else fail_silently,
            use_ssl=db_settings.email_use_ssl if use_ssl is None else use_ssl,
            timeout=db_settings.timeout if timeout is None else timeout,
            ssl_keyfile=ssl_keyfile,
            # TODO: ssl_keyfile=db_settings.ssl_keyfile if ssl_keyfile is not None else ssl_keyfile,
            ssl_certfile=ssl_certfile,
            # TODO: ssl_certfile=db_settings.ssl_certfile if ssl_certfile is not None else ssl_certfile,
            **kwargs
        )


__all__ = ['ConfiguredEmailBackend']
