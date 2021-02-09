from .base_dispatcher import BaseDispatcher


class PrintToScreenDispatcher(BaseDispatcher):
    """
    This dispatcher is intended for testing purposes only.

    Rather than dispatch a message to another service, this just
    writes the payload to the screen.
    """
    def on_event(self, payload):
        print(str(payload))
        self.on_completion(payload)
