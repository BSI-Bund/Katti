

def route_task(name, args, kwargs, options, task=None, **kw):
    if 'ssl_scanning_task' in name:
        return {'queue': 'ssl_scanning',
                'routing_key': 'sll_scanning'}
    if 'CeleryApps.ScanningTasks' in name:
        return {'queue': 'scanning',
                'routing_key': 'scanning'}
    if 'CeleryApps.PeriodicSystemTasks' in name:
        return {'queue': 'periodic_tasks',
                'routing_key': 'periodic'}
    if 'CeleryApps.DataFeedTasks' in name:
        return {'queue': 'feeds',
                'routing_key': 'feed'}
    if 'CeleryApps.CrawlingTasks.crawling_request_celery' in name:
        return {'queue': 'crawling_request',
                'routing_key': 'crawling.request'}
    if 'CeleryApps.CrawlingTasks.crawling_task' in name:
        return {'queue': 'crawler',
                'routing_key': 'crawling.crawler'}
    if 'CeleryApps.CrawlingTasks.bundle_analysis' in name:
        return {'queue': 'bundle_analysis',
                'routing_key': 'crawling.analysis'}
    if 'CeleryApps.TelegramTasks' in name:
        return {'queue': 'telegram',
                'routing_key': 'telegram'}
    if 'CeleryApps.ReportTasks' in name:
        return {'queue': 'report_tasks',
                'routing_key': 'report_tasks'}
    if 'CeleryApps.LongRunningRequests' in name:
        return {'queue': 'long_running',
                'routing_key': 'long_running'}

    if 'CeleryApps.CrawlingTasks' in name:
        return {'queue': 'crawling_default',
                'routing_key': 'crawling_default'}

    if 'generate_pdf_report' in name:
        return {'queue': 'pdf_generation',
                'routing_key': 'pdf_generation'}

    return {'queue': 'default', 'routing_key': 'default'}
