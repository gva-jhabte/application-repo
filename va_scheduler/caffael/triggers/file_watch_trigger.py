from .base_trigger import BasePollingTrigger
import datetime
import pathlib
from ..exceptions import MissingInformationError


class FileWatchTrigger(BasePollingTrigger):
    """
    Watch for the presence of a file; the filename can contain
    markers for date formatting.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'filename' not in kwargs:
            raise MissingInformationError("FileWatchTrigger requires 'filename' parameter")
        self.filename = kwargs['filename']
        self.last_filename = None
        if self.label:
            self.label = self.label + " - " + self.filename
        else:
            self.label = self.filename

    def nudge(self):
        # build filename, 
        filename = datetime.datetime.today().strftime(self.filename)
        # does the filename exist
        path = pathlib.Path(filename)
        if path.is_file() and path != self.last_filename:
            self.on_event(filename)
            self.last_filename = path
            return True
        return False
