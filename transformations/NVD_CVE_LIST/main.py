"""
NVD_CVE_LIST
"""
from flask import Flask
import datetime
from gva.data.validator import Schema
from gva.flows.operators import EndOperator, SaveToBucketOperator
from operators import AcquireAnnualCveDataOperator, SplitCveDataOperator
from gva.utils.common import build_context
from flask_sslify import SSLify
from flask_cors import CORS
import sqlalchemy
import os
from datetime import date
from google.cloud import secretmanager



from gva.logging import get_logger
logger = get_logger()
logger.setLevel(5)

app = Flask(__name__)
CORS(app, supports_credentials=True)
date = date.today()

# sslify = SSLify(app)

client = secretmanager.SecretManagerServiceClient()

username = client.access_secret_version(request={"name": "projects/311966843135/secrets/dbuser/versions/1"})
password = client.access_secret_version(request={"name": "projects/311966843135/secrets/dbpass/versions/1"})
name = client.access_secret_version(request={"name": "projects/311966843135/secrets/dbname/versions/1"})
# dbhost = '127.0.0.1:5432'
db_user = username.payload.data.decode("UTF-8")
db_pass = password.payload.data.decode("UTF-8")
db_name = name.payload.data.decode("UTF-8")
# db_host = dbhost.payload.data.decode("UTF-8")
db_host = '127.0.0.1:5432'
def init_connection_engine():
    db_config = {
        # [START cloud_sql_postgres_sqlalchemy_limit]
        # Pool size is the maximum number of permanent connections to keep.
        "pool_size": 5,
        # Temporarily exceeds the set pool_size if no connections are available.
        "max_overflow": 2,
        # The total number of concurrent connections for your application will be
        # a total of pool_size and max_overflow.
        # [END cloud_sql_postgres_sqlalchemy_limit]

        # [START cloud_sql_postgres_sqlalchemy_backoff]
        # SQLAlchemy automatically uses delays between failed connection attempts,
        # but provides no arguments for configuration.
        # [END cloud_sql_postgres_sqlalchemy_backoff]

        # [START cloud_sql_postgres_sqlalchemy_timeout]
        # 'pool_timeout' is the maximum number of seconds to wait when retrieving a
        # new connection from the pool. After the specified amount of time, an
        # exception will be thrown.
        "pool_timeout": 30,  # 30 seconds
        # [END cloud_sql_postgres_sqlalchemy_timeout]

        # [START cloud_sql_postgres_sqlalchemy_lifetime]
        # 'pool_recycle' is the maximum number of seconds a connection can persist.
        # Connections that live longer than the specified amount of time will be
        # reestablished
        "pool_recycle": 1800,  # 30 minutes
        # [END cloud_sql_postgres_sqlalchemy_lifetime]
    }

    if db_host:
        return init_tcp_connection_engine(db_config)
    else:
        return init_unix_connection_engine(db_config)


def init_tcp_connection_engine(db_config):
    # [START cloud_sql_postgres_sqlalchemy_create_tcp]
    # Remember - storing secrets in plaintext is potentially unsafe. Consider using
    # something like https://cloud.google.com/secret-manager/docs/overview to help keep
    # secrets secret.

    # Extract host and port from db_host
    host_args = db_host.split(":")
    db_hostname, db_port = host_args[0], int(host_args[1])

    pool = sqlalchemy.create_engine(
        # Equivalent URL:
        # postgres+pg8000://<db_user>:<db_pass>@<db_host>:<db_port>/<db_name>
        sqlalchemy.engine.url.URL(
            drivername="postgresql+pg8000",
            username=db_user,  # e.g. "my-database-user"
            password=db_pass,  # e.g. "my-database-password"
            host=db_hostname,  # e.g. "127.0.0.1"
            port=db_port,  # e.g. 5432
            database=db_name  # e.g. "my-database-name"
        ),
        **db_config
    )
    # [END cloud_sql_postgres_sqlalchemy_create_tcp]
    pool.dialect.description_encoding = None
    return pool


def init_unix_connection_engine(db_config):
    # [START cloud_sql_postgres_sqlalchemy_create_socket]
    # Remember - storing secrets in plaintext is potentially unsafe. Consider using
    # something like https://cloud.google.com/secret-manager/docs/overview to help keep
    # secrets secret.

    db_socket_dir = os.environ.get("DB_SOCKET_DIR", "/cloudsql")
    cloud_sql_connection_name = os.environ["CLOUD_SQL_CONNECTION_NAME"]

    pool = sqlalchemy.create_engine(

        # Equivalent URL:
        # postgres+pg8000://<db_user>:<db_pass>@/<db_name>
        #                         ?unix_sock=<socket_path>/<cloud_sql_instance_name>/.s.PGSQL.5432
        sqlalchemy.engine.url.URL(
            drivername="postgresql+pg8000",
            username=db_user,  # e.g. "my-database-user"
            password=db_pass,  # e.g. "my-database-password"
            database=db_name,  # e.g. "my-database-name"
            query={
                "unix_sock": "{}/{}/.s.PGSQL.5432".format(
                    db_socket_dir,  # e.g. "/cloudsql"
                    cloud_sql_connection_name)  # i.e "<PROJECT-NAME>:<INSTANCE-REGION>:<INSTANCE-NAME>"
            }
        ),
        **db_config
    )
    # [END cloud_sql_postgres_sqlalchemy_create_socket]
    pool.dialect.description_encoding = None
    return pool


# This global variable is declared with a value of `None`, instead of calling
# `init_connection_engine()` immediately, to simplify testing. In general, it
# is safe to initialize your database connection pool when your script starts
# -- there is no need to wait for the first request.
db = None

def build_flow(context: dict):

    global db
    db = init_connection_engine()
    # Create tables (if they don't already exist)
    with db.connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS nvd_state "
            "( data_feed VARCHAR(255), date DATE, "
            "last_state VARCHAR(255));"
            "INSERT INTO nvd_state (data_feed, date)"
            f"VALUES ('nvd-list','{date}');"
        )
    # define the operations in the flow

    acquire = AcquireAnnualCveDataOperator()
    modify_tables('acquire')

    split = SplitCveDataOperator()
    modify_tables('split')
    save_to_bucket = SaveToBucketOperator(
            project=context['config'].get('target_project'),
            to_path=context['config'].get('target_path'),
            schema=Schema(context),
            date=context.get('date'),
            compress=context['config'].get('compress'))
    modify_tables('save_to_bucket')
    end = EndOperator()

    # chain the operations to create the flow
    flow = acquire > split > save_to_bucket > end

    # attach the writers
    flow.attach_writers(context['config'].get('writers', []))

    return flow

def modify_tables(last_state):
    conn = None
    try:
        db = init_connection_engine()
        conn = db.connect()
        conn.execute(
            "UPDATE nvd_state " 
            f"SET last_state = '{last_state}' "
            f"WHERE date = '{date}';"
        )
        conn.close()
    except (Exception) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()

@app.route('/ingest', methods=["POST"])
def main(context: dict = {}):
    context['config_file'] = 'NVD_CVE_LIST.metadata'
    # create the run context from the config and context passed to main
    # this would allow dates etc to be passed from something external
    context = build_context(**context)

    # create the flow
    flow = build_flow(context)

    # NVD files are separate files per year
    currentYear = datetime.datetime.now().year
    for year in range(2018, currentYear + 1):
        my_context = context.copy()
        my_context['year'] = year
        flow.run(
            data={},
            context=my_context,
            trace_sample_rate=context['config'].get('sample_rate'))

    # finalize the operators
    summary = flow.finalize()
    logger.trace(summary)
    modify_tables('end')
    return 'Finished Ingest'

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
    # app.run(ssl_context="adhoc", host="0.0.0.0", port=8080)