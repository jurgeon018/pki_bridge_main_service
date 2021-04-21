from .pki_bridge import BASE_DIR


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "short": {"format": "%(name)-12s %(levelname)-8s %(message)s"},
        "long": {"format": "%(asctime)s %(name)-16s %(funcName)-12s %(levelname)-8s %(message)s"},
        "full": {
            "format": "\nasctime: %(asctime)-12s \ncreated: %(created)-12f \nfilename: %(filename)-12s \nfuncName: %(funcName)-12s \nlevelname: %(levelname)-12s \nlevelno: %(levelno)-12s \nlineno: %(lineno)-12d \nmessage: %(message)-12s \nmodule: %(module)-12s \nmsecs: %(msecs)-12d \nname: %(name)-12s \npathname: %(pathname)-12s \nprocess: %(process)-12d \nprocessName: %(processName)-12s \nrelativeCreated: %(relativeCreated)-12d \nthread: %(thread)-12d \nthreadName: %(threadName)-12s\n"
        },
    },
    "handlers": {
        "null": {
            "level": "DEBUG",
            "class": "logging.NullHandler",
        },
        "console": {"level": "DEBUG", "class": "logging.StreamHandler", "formatter": "short"},
        "debug_file": {"level": "DEBUG", "class": "logging.FileHandler", "formatter": "long", "filename": BASE_DIR / "debug.log"},
        "warning_file": {"level": "WARNING", "class": "logging.FileHandler", "formatter": "long", "filename": BASE_DIR / "warning.log"},
        "error_file": {"level": "ERROR", "class": "logging.FileHandler", "formatter": "long", "filename": BASE_DIR / "error.log"},
    },
    "loggers": {
        "": {
            "level": "WARNING",
            "handlers": [
                "debug_file",
                "warning_file",
                "error_file",
            ],
            "propagate": False,
        },
    },
}
