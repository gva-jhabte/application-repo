
from .base_trigger import BasePollingTrigger
import datetime


class IntervalTrigger(BasePollingTrigger):
    """
    Trigger based on an interval
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.interval = kwargs.get('interval', 60)
        if self.label:
            self.label = self.label + " - " + str(self.interval) + "s"
        else:
            self.label = str(self.interval) + "s"

    def nudge(self):
        """
        test if the condition to run has been met
        """
        self.on_event(datetime.datetime.now().isoformat())
        return True

