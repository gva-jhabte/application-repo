"""
Auditor

Writes event information from the transformation pipelines
to StackDriver for audit and logging purposes.
"""
from google.cloud import logging # type:ignore
import datetime

class Auditor(object):
    """
     Records data for simple quality and performance monitoring for transformations

    Parameters:
        data_set: name of the target data set
        none: legacy field - not used
        log: the stackdriver log name
    """

    def __init__(self, data_set=None, log='va-transformations'):
        if log and log.lower().endswith('ml'):
            log = 'va-transformations'
        if not log:
            raise Exception('auditor must be initialized with the log value set.')
        if data_set == None:
            raise Exception('auditor must be initialized with the data_set value set.')
        
        self.log = log

        self.data_set = data_set
        self.commencement_time = None
        self.completion_time = None
        self.records_read = 0
        self.records_written = 0


    def format_event(self):
        """
        Creates a Dictionary of the values recorded, calculates task duration.
        """
        record = { 
            "data_set": self.data_set,
            "commencement_time": self.commencement_time.isoformat(),
            "completion_time": self.completion_time.isoformat(),
            "task_duration_seconds": (self.completion_time - self.commencement_time).total_seconds(),
            "records_read": self.records_read,
            "records_written": self.records_written
        }
        return record


    def log_event(self):
        """
        Saves the event to the specified Log Sink
        """
        record = self.format_event()
        self.logging_client = logging.Client()
        self.logger = self.logging_client.logger(self.log)
        self.logger.log_struct(record)


    # required to use class as a contextmanager, that is:
    # with Auditor() as a:
    def __enter__(self):
        self.commencement_time = datetime.datetime.now()
        self.completion_time = None
        self.records_read = 0
        self.records_written = 0
        return self


    # required to use class as a contextmanager
    def __exit__(self, type, value, traceback):
        self.completion_time = datetime.datetime.now()
        self.log_event()
        print(F'job {self.data_set} completed. {self.records_read}/{self.records_written}')
