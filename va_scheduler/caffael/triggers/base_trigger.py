"""
Trigger Base Class
"""
import abc
from ..exceptions import StopTrigger, MissingInformationError
import time
import datetime


class BaseTrigger(abc.ABC):
    """
    Base Trigger
    """
    def __init__(self, *args, **kwargs):
        self.queue_name = self.__class__.__name__
        self.label = kwargs.get('label')
        if 'dispatcher' not in kwargs:
            raise MissingInformationError("Triggers must have a 'dispatcher' assigned")
        self.dispatcher = kwargs.pop('dispatcher')

    def __str__(self):
        if self.label:
            return f"{self.__class__.__name__} ({self.label})"
        return f"{self.__class__.__name__}"

    @abc.abstractmethod
    def engage(self, flow):
        """
        'engage' is called when a trigger is loaded.
        This should start any listening activities - like
        subscribing to message queues.
        """
        raise NotImplementedError("Trigger function 'engage' must be overridden")

    def on_event(self, payload):
        """
        DO NOT OVERRIDE THIS METHOD
        """

        print({"date": datetime.datetime.now().isoformat(),
            "trigger": str(self),
            "dispatcher": str(self.dispatcher)})

        self.dispatcher.on_event(payload)


class BasePollingTrigger(BaseTrigger):
    """
    Base Polling Trigger
    parameters
    - interval: the number of seconds between polls
    - max_runs: the number of times to execute the flow from this
                trigger, -1 = run forever
    """
    def __init__(self, *args, **kwargs):
        """
        max runs < 0 = run until stopped
        """
        super(BasePollingTrigger, self).__init__(*args, **kwargs)
        self.polling_interval = kwargs.get('interval', 60)
        self.max_runs = kwargs.get('max_runs', -1)

    @abc.abstractmethod
    def nudge(self):
        """
        This must call on_event with the data to pass to the
        pipeline.
        This method should return True if the nudge triggered.
        """
        raise NotImplementedError("'nudge' must be overridden")

    def engage(self):
        while self.max_runs != 0:
            self.nudge()
            time.sleep(self.polling_interval)
        raise StopTrigger('Max runs completed')

    def on_event(self, payload):
        """
        DO NOT OVERRIDE THIS METHOD
        """
        self.max_runs -= 1
        super().on_event(payload)
