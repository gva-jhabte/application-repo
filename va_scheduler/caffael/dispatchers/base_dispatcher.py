import abc


class BaseDispatcher(abc.ABC):

    def __init__(self, *args, **kwargs):
        self.label = kwargs.get('label')
        self.args = args
        self.kwargs = kwargs

    @abc.abstractmethod
    def on_event(self, *arg, **kwargs):
        raise NotImplementedError("Dispatcher 'on_event' must be overriden.")

    def on_completion(self, *arg, **kwargs):
        # on_completion should be called when the task is complete
        pass

    def __str__(self):
        if self.label:
            return f"{self.__class__.__name__} ({self.label})"
        return f"{self.__class__.__name__}"
