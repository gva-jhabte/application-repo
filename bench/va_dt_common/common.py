"""
Common Library for VAP Data Transformations
"""
from google.cloud import storage # type:ignore
import re
import os
import datetime
import tempfile
import os.path
import csv, yaml
try:
    import ujson as json
except ImportError:
    import json # type:ignore
import warnings


def read_blob_lines(project, bucket, blob_name, chunk_size=32*1024*1024, delimiter='\n'):
    """
    Reads lines from an arbitrarily long blob, line by line
    
    Parameters:
        project: GCP project
        bucket: GCS bucket
        blob_name: GCS blob - regex match on blob name
        chunk_size: (optional) number of characters to read at a time (default = 1Mb)
        delimiter: (optional) the record separator in the blob (default = new line)
        
    Returns an generator of lines in the file
    """
    
    client = storage.Client(project=project)
    bucket = client.get_bucket(bucket)
    blob = bucket.get_blob(blob_name)
    blob_size = blob.size

    carry_forward = ''
    cursor = 0
    while (cursor < blob_size):
        chunk = blob.download_as_string(start=cursor, end=min(blob_size, cursor+chunk_size-1))   
        cursor = cursor + len(chunk)
        chunk = chunk.decode('utf-8')
        # add the last line from the previous cycle
        chunk = carry_forward + chunk
        lines = chunk.split(delimiter)
        # the list line is likely to be incomplete, save it to carry forward
        carry_forward = lines.pop()
        yield from lines
    if len(carry_forward) > 0:
        yield carry_forward


def get_temp_file(job_name):
    warnings.warn("'get_temp_file' will be deprecated, remove any use of this method")
    """
    Returns a temporary file path
    """
    TEMP_PATH = os.path.expanduser('~/TEMP/')
    os.makedirs(TEMP_PATH, exist_ok=True)
    return os.path.join(TEMP_PATH, job_name)
    
    
def _extract_date_string(path):
    """
    extract a YYYY-MM-DD format date from a longer string.
    """
    date_extractor = r"([1-2][0-9]{3}-[0-1][0-9]-[0-3][0-9])"
    match = re.search(date_extractor, path)
    if match:
        return match.group(0)
    return None


def _get_latest_date(blob_list):
    """
    Get the latest date from a set of strings.   
    In YYYY-MM-DD format, we can sort them as strings.
    """
    latest_date = "0000-00-00"
    for blob in blob_list:
        mydate = _extract_date_string(blob.name)
        if mydate != None:
            if mydate > latest_date:
                latest_date = mydate
    return latest_date


def get_list_of_blobs(project, bucket, path, only_latest_date=True):
    """
    Create an generator for the files in a given pseudo path in a storage bucket.

    Parameters
        bucketname: the name of the storage bucket
        path: the pseudo path to the set of files

    Path is treated with a regex and latest date filter
    """
    client = storage.Client(project=project)
    bucket = client.get_bucket(bucket)
    
    # all blobs in the bucket that match filename
    blob_list = filter(lambda blob: re.findall(path, blob.name, re.IGNORECASE), bucket.list_blobs())

    if only_latest_date:
        blob_list = list(blob_list) # we're going to iterate over this twice 
        # all blobs in the bucket that match filename from latest date
        latest_date = _get_latest_date(blob_list)
        blob_list = filter(lambda blob: blob.name.find(latest_date) > 0, blob_list)
    
    for blob in blob_list:
        yield blob
        
        
def read_config(config_file):
    with open(config_file, 'r') as f:
        yaml_config = yaml.safe_load(f)
    return yaml_config


def save_file_to_bucket(source_file, project, bucket, path):
    warnings.warn("'save_file_to_bucket' is a deprecation target")
    """
    Copy a local file to a storage bucket
    
    Parameters:
        source_file: file to be copied
        bucket_name: destination storage bucket
        destination_file: destination file within bucket, including any pseudo path
    """
    client = storage.Client(project=project)
    bucket = client.get_bucket(bucket)
    path = path.replace('%date', '%Y-%m-%d')
    blob = bucket.blob(datetime.datetime.today().strftime(path))
    blob.upload_from_filename(source_file)
    
    
def write_text_line(data, file_name):
    warnings.warn("'write_text_line' will be deprecated, remove any use of this method")
    # to be deprecated
    """
    Saves a line to a file
    """
    with open(file_name, "a+", encoding='utf-8') as f:
        f.write(str(data).rstrip('\n|\r') + '\n')


def write_json_line(data, file_name):
    warnings.warn("'write_json_line' will be deprecated, remove any use of this method")
    # to be deprecated
    """
    Writes a line of JSON to a file
    """
    write_text_line(json.dumps(data, ensure_ascii=False), file_name)


def select_fields(dic, fields):
    """
    Selects a subset of fields from a dictionary
    """
    return { k: dic.get(k, None) for k in fields }


def _select_all(dummy):
    return True


def select_file_records(project, bucket, path, columns=['*'], condition=_select_all, only_latest_date=True):
    """
    Scan a json lines blob, filtering rows and selecting columns.

    Basic implementation of SQL SELECT statement for a single table

    SELECT <columns> FROM <path> WHERE <condition>
    """
    for blob in get_list_of_blobs(project, bucket, path, only_latest_date):
        for line in read_blob_lines(project, bucket, blob.name):
            data_record = json.loads(line)
            if condition(data_record):
                if columns != ['*']:
                    data_record = select_fields(data_record, columns)
                yield data_record


def union_file_records(list_of_lists, columns=['*'], condition=_select_all):
    """
    Append the records from a set of lists together.

    Basic implementation of SQL UNION statement.

    SELECT <columns> FROM <list_of_lists[0]> WHERE <condition>
    UNION
    SELECT <columns> FROM <list_of_lists[1]> WHERE <condition>
    ...
    """
    for data_list in list_of_lists:
        for data_record in data_list:
            if condition(data_record):
                if columns != ['*']:
                    data_record = select_fields(data_record, columns)
                yield data_record


def create_index(project, bucket, path, index_column, index_data=['*'], condition=_select_all):
    warnings.warn("'create_index' is a deprecation target")
    """
    Create an index of a file to speed up look-ups.
    """

    index = { }

    for blob in get_list_of_blobs(project, bucket, path):
        for line in read_blob_lines(project, bucket, blob.name):
            data_record = json.loads(line)
            if condition(data_record):
                index_value = data_record[index_column]
                if condition != ['*']:
                    data_record = select_fields(data_record, index_data)
                index[index_value] = data_record
    return index


def find_cves(string):
    tokens = re.findall(r"(?i)CVE.\d{4}-\d{4,7}", string) 
    result = []
    for token in tokens:
        token = token.upper().strip()
        token = token[:3] + '-' + token[4:]  # snort rules list cves as CVE,2009-0001
        result.append(token)
    return result

def daterange():
    """ Get the start and end date from the common_config. These should be applicable to any script
    #obtaining its date through this route, so ensures consistency of date processing for a given orchestrated run"""
    
    # Not certain where this common lib will be imported from, so search up two levels (matches sys.path used in
    # file parsing scripts) to find the common_config.yaml 
    if os.path.isfile('common_config.yaml'):
        CONFIG_FILE = 'common_config.yaml'
    elif os.path.isfile('../va_dt_common/common_config.yaml'):
        CONFIG_FILE = '../va_dt_common/common_config.yaml'
    else:
        CONFIG_FILE = '../../va_dt_common/common_config.yaml'
            
    config = read_config(CONFIG_FILE)
    try: 
        # Attempt to convert incoming yaml data into dates
        start_date = datetime.datetime.strptime(config.get('start_date'), '%Y-%m-%d')
        end_date = datetime.datetime.strptime(config.get('end_date'), '%Y-%m-%d')
    except:
        # If either of these are not valid dates, then presume that this is a conventional run for a single
        # date. Represent this by setting the start and end dates to now
        start_date = datetime.datetime.now()
        end_date = datetime.datetime.now()
        
    # Return a generator over the requested range (or for the single date)
    for n in range(int((end_date - start_date).days) + 1):
        yield start_date + datetime.timedelta(n)

def compare_data_in_blobs(first_project, first_bucket, first_blob_name, second_project, second_bucket, second_blob_name):
    """ allows comparison between the data held in two blobs on a line by line basis. Note that the lines
     are loaded into a set and a diff then carried out, so the original blobs do not have to have the
     lines in the same order, they merely have to have the same lines.
    
     returns True if blobs contain matching data, False otherwise """
    set1 = set()
    set2 = set()
    for line in read_blob_lines(first_project, first_bucket, first_blob_name):
        set1.add(line)

    for line in read_blob_lines(second_project, second_bucket, second_blob_name):
        set2.add(line)    

    if len(set1)==len(set2):
        # Blobs have the same number of lines, so do set.difference to see if there are any mismatched
        difference = set1.difference(set2)
        if len(difference)==0:
            # No differences, so...
            return True
    
    # Either the lengths were different, or there were differences in lines, so...
    return False

def compare_data_blob_and_set(fproject, bucket, blob_name, set_of_data_lines):
    """ allows comparison between the data held in a blob with that in a set on a line by line basis. Note that
     the blob lines are loaded into a set and a diff then carried out, so the original data do not have to have the
     lines in the same order, they merely have to have the same lines.
    
     returns True if data matches, False otherwise """
    set1 = set()
    set2 = set_of_data_lines
    for line in read_blob_lines(fproject, bucket, blob_name):
        set1.add(line)  

    if len(set1)==len(set2):
        # data sources have the same number of lines, so do set.difference to see if there are any mismatched
        difference = set1.difference(set2)
        if len(difference)==0:
            # No differences, so...
            return True
    
    # Either the lengths were different, or there were differences in lines, so...
    return False


class temp_file(object):
    """
    A class to handle some of the repeat activities for dealing
    with temporary files.
    """
    
    def __init__(self, job_name=None, auditor=None):
        """
        Create the file
        """
        # use the tempfile library
        self.__file_object = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        self.file_name = self.__file_object.name

        # as this class is usually writing the records to disk
        # we can count them here
        self.auditor = auditor

        # record the number of records
        self.length = 0


    def __len__(self):
        """
        Return the number of records written

        len(t)
        """
        return self.length


    def __str__(self):
        """
        Return the filename

        str(t)
        """
        return self.file_name


    def __call__(self):
        """
        Direct access to file object
        
        t()
        """
        if self.auditor:
            self.auditor = None
            warnings.warn('Accessing the temp_file underlying file object disabled automatic auditting')
        return self.__file_object


    def write_text_line(self, line):
        """
        Write a line of text to the file
        """
        self.length += 1
        line = str(line).rstrip('\n|\r') + '\n'
        self.__file_object.write(line)


    def write_json_line(self, record):
        """
        Convert a dict to a string and write to the file
        """
        self.write_text_line(json.dumps(record, ensure_ascii=False))


    def save_to_bucket(self, project, bucket, blob_name):
        
        if self.auditor:
            self.auditor.records_written = self.length

        self.__file_object.flush()

        client = storage.Client(project=project)
        bucket = client.get_bucket(bucket)
        path = blob_name.replace('%date', '%Y-%m-%d')
        blob = bucket.blob(datetime.datetime.today().strftime(path))
        blob.upload_from_filename(self.file_name)


    def __del__(self):
        """
        Tidy Up
        """
        self.__file_object.close()
        if os.path.exists(self.file_name):
            os.remove(self.file_name)
