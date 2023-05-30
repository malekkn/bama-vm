from cle.backends import Blob, register_backend
from archinfo import arch_from_id
import re
import logging

l = logging.getLogger("cle.blob")

__all__ = ('MBF',)

class MBF(Blob):
    """
    Representation of a binary blob, i.e. an executable in an unknown file format.
    """
    is_default = True

    def __init__(self, *args, offset=0, **kwargs):
        """
        Loader backend for BF programs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        """
        super(MBF, self).__init__(*args,
                arch=arch_from_id("mbf"),
                offset=offset,
                entry_point=0,
                **kwargs)
        self.os = "mbf"

    @staticmethod
    def is_compatible(stream):
        bf_re = re.compile(b'[+\-<>.,\[\]\n()&@v\^#|]+')
        stream.seek(0)
        stuff = stream.read(0x1000)
        if bf_re.match(stuff):
            return True
        return True

register_backend("mbf", MBF)
