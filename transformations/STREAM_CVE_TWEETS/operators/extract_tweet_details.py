from gva.flows import BaseOperator


class ExtractTweetDetailsOperator(BaseOperator):

    def execute(self, data, context):
        try:
            quoting = data.quoted_status_id
        except AttributeError:
            quoting = None

        retweeting = None
        full_text = None
        if hasattr(data, "retweeted_status"):
            try:
                retweeting = data.retweeted_status.id
                full_text = data.retweeted_status.extended_tweet["full_text"]
            except AttributeError:
                full_text = data.retweeted_status.text
        else:
            try:
                full_text = data.extended_tweet["full_text"]
            except AttributeError:
                full_text = data.text

        try:
            hash_tags = [[tag for key,tag in hash_tag.items() if key == 'text'] for hash_tag in data.entities.get('hashtags')]
            hash_tags = [item for sublist in hash_tags for item in sublist]
        except KeyError:
            hash_tags = []

        new_payload = {
            "tweet_id": data.id,
            "text": full_text,
            "timestamp": data.timestamp_ms,
            "user_id": data.user.id,
            "user_verified": data.user.verified,
            "user_name": data.user.name,
            "hash_tags": hash_tags,
            "followers": data.user.followers_count,
            "following": data.user.friends_count,
            "tweets_by_user": data.user.statuses_count,
            "is_quoting": quoting,
            "is_reply_to": data.in_reply_to_status_id,
            "is_retweeting": retweeting
        }

        return new_payload, context
