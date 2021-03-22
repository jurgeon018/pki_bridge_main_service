from django import apps


class PkiBridgeConfig(apps.AppConfig):
    name = 'pki_bridge'
    verbose_name = 'Pki Bridge'
    verbose_name_plural = verbose_name


default_app_config = 'pki_bridge.PkiBridgeConfig'
