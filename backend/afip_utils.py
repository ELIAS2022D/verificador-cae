import datetime

def afip_time_now():
    return datetime.datetime.utcnow()

def afip_time_fmt(dt: datetime.datetime):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")
