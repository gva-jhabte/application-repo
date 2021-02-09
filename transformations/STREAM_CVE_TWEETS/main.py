import tweepy
from operators import ExtractCvesFromTweetOperator, ExtractTweetDetailsOperator
import time
from gva.flows.operators import EndOperator, SaveToBucketOperator
from gva.data.validator import Schema
from gva.utils.common import build_context

try:
    from rich import traceback
    traceback.install()
except ImportError:
    pass

import gva.logging
logger = gva.logging.get_logger()
logger.setLevel(5)

# secrets here
api = tweepy.API(auth, wait_on_rate_limit=True, wait_on_rate_limit_notify=True)

try:
    api.verify_credentials()
    print("Authentication OK")
except Exception as err:
    print("Error during authentication - ", err)


class TwitterListener(tweepy.StreamListener):

    def __init__(self, api, flow):
        self.counter = 0
        self.api = api
        self.me = api.me()
        self.flow = flow

    def on_status(self, tweet):
        self.counter += 1
        print(F"{time.time_ns()} - {self.counter} - {len(str(tweet))}")
        self.flow.run(data=tweet, context={}, trace_sample_rate=0)

    def on_error(self, status):
        print("Error detected - ", str(status))


def main(context):
    
    # create the run context from the config and context passed to main
    # this would allow dates etc to be passed from something external
    context = build_context(**context)

    extract_tweet = ExtractTweetDetailsOperator()
    extract_cves = ExtractCvesFromTweetOperator()
    save = SaveToBucketOperator(
            project=context['config'].get('target_project'),
            to_path=context['config'].get('target_path'),
            schema=Schema(context),
            compress=context['config'].get('compress'))
    end = EndOperator()

    flow = extract_tweet > extract_cves > save > end

    while True:
        try:
            listener = TwitterListener(api, flow)
            stream = tweepy.Stream(api.auth, listener, tweet_mode="extended")
            stream.filter(track=["CVE"], languages=["en"])
        except KeyboardInterrupt:
            print('Keyboard Interrupt')
            quit()
        except Exception as err:
            print(F"Error {type(err).__name__} {err} - restarting in 5 seconds")
            print(gva.errors.RenderErrorStack())

        time.sleep(5)


if __name__ == "__main__":
    context = {}
    context['config_file'] = 'STREAM_CVE_TWEETS.metadata'
    main(context)

