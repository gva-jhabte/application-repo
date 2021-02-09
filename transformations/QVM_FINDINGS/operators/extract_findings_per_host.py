from gva.flows import BaseOperator
import datetime


class ExtractFindingsPerHost(BaseOperator):

    def _reformat_date(self, in_date: str) -> str:
        if in_date:
            return datetime.datetime.strptime(in_date, "%Y-%m-%dT%H:%M:%SZ").isoformat()
        return None

    def execute(self, data, context):

        ID = data.get('ID')
        IP = data.get('IP')
        OS = data.get('OS')
        DNS = data.get('DNS')
        NETBIOS = data.get('NETBIOS')
        LAST_SCAN_DATETIME = self._reformat_date(data.get('LAST_SCAN_DATETIME'))
        LAST_VM_SCANNED_DATE = self._reformat_date(data.get('LAST_VM_SCANNED_DATE'))
        LAST_VM_SCANNED_DURATION = data.get('LAST_VM_SCANNED_DURATION')
        LAST_VM_AUTH_SCANNED_DATE = self._reformat_date(data.get('LAST_VM_AUTH_SCANNED_DATE'))

        detections = data.get('DETECTION_LIST')['DETECTION']
        if not type(detections) is list:
            detections = [detections]
        
        for detection in detections:
            
            yield ({ 
                "QID": detection.get('QID'), 
                "TYPE": detection.get('TYPE'),
                "SEVERITY": detection.get('SEVERITY'),
                "SSL": detection.get('SSL'),
                "RESULTS": detection.get('RESULTS'),
                "STATUS": detection.get('STATUS'),
                "FIRST_FOUND_DATETIME": self._reformat_date(detection.get('FIRST_FOUND_DATETIME')),
                "LAST_FOUND_DATETIME": self._reformat_date(detection.get('LAST_FOUND_DATETIME')),
                "TIMES_FOUND": detection.get('TIMES_FOUND'),
                "LAST_TEST_DATETIME": self._reformat_date(detection.get('LAST_TEST_DATETIME')),
                "LAST_UPDATE_DATETIME": self._reformat_date(detection.get('LAST_UPDATE_DATETIME')),
                "IS_IGNORED": detection.get('IS_IGNORED'),
                "IS_DISABLED": detection.get('IS_DISABLED'),
                "LAST_PROCESSED_DATETIME": self._reformat_date(detection.get('LAST_PROCESSED_DATETIME')),
                "PORT": detection.get('PORT'),

                "ID": ID,
                "IP": IP,
                "QUALYS_OS": OS,
                "DNS": DNS,
                "NETBIOS": NETBIOS,
                "LAST_SCAN_DATETIME": LAST_SCAN_DATETIME,
                "LAST_VM_SCANNED_DATE": LAST_VM_SCANNED_DATE,
                "LAST_VM_SCANNED_DURATION": LAST_VM_SCANNED_DURATION,
                "LAST_VM_AUTH_SCANNED_DATE": LAST_VM_AUTH_SCANNED_DATE
            }, context)