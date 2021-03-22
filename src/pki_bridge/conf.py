import logging

from pki_bridge.models import ProjectSettings


logger = logging.getLogger(__name__)


class DbSettings:

    def __getattr__(self, setting):
        project_settings = ProjectSettings.get_solo()
        if hasattr(project_settings, setting):
            attr = getattr(project_settings, setting)
            return attr
        else:
            msg = f'Setting "{setting}" doesnt exist.'
            logger.error(msg)
            print(1)
            raise Exception(msg)

db_settings = DbSettings()
