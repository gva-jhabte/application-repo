import threading
import time
from ..exceptions import StopTrigger


def _schedule_thread_runner(trigger,
                        restart_on_error=True,
                        restart_delay_seconds=5):

    # we always want to run at least once
    keep_running_trigger = True
    while keep_running_trigger:
        keep_running_trigger = restart_on_error
        try:
            trigger.engage()
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except MemoryError:
            raise MemoryError()
        except StopTrigger:
            keep_running_trigger = False
        except Exception as e:
            print('EXCEPTION:', e)   # TODO: log this error
        time.sleep(restart_delay_seconds)
    print(f"Scheduler Thread {threading.current_thread().name} has terminated")


class Scheduler(object):
    """
    The Scheduler wraps a set of trigger/dispatch sets.

    You can run these outside the Scheduler, however the scheduler
    does some things for you:

    - it's non-blocking, you can run the trigger whilst doing other
      work
    - it's multi-threaded, you can run multiple triggers
    - it resumes failed triggers
    - TODO: it will allow querying of states of triggers
    """

    def __init__(self):
        self._threads = []

    def add_trigger(self, trigger, restart_on_error=True, restart_delay_seconds=5):
        event_thread = threading.Thread(
            target=_schedule_thread_runner, args=(trigger, restart_on_error, restart_delay_seconds)
        )
        event_thread.daemon = True
        event_thread.setName(F"scheduler:{str(trigger)}")
        self._threads.append(event_thread)

    def execute(self):
        """
        Start each of the flow trigger threads
        """
        [t.start() for t in self._threads]

    def running(self):
        """
        Are any thread still running?
        """
        return any([t.is_alive() for t in self._threads])

    def read_sensors(self):
        """
        TODO: build status information
        triggers : {
            type: classname
            label: label
            activated_count: mss
            running_since: mmmm
            current_state: sss
            state_since: sss
            dispatcher: sss
        }
        """
        readings = {}
        readings['event_handlers'] = [t.read_sensors() for t in self._threads if t.is_alive()]
        return readings
