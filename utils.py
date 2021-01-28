# -*- coding: utf-8 -*-


from math import ceil


def split_upload_bulk(data, bulk_size=50):
    for bulk in range(ceil(len(data) / bulk_size)):
        yield data[bulk_size * bulk: bulk_size * (bulk + 1)]
