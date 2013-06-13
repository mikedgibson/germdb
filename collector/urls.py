from django.conf.urls import patterns, include, url

urlpatterns = patterns('collector.views',
    url(r'^$', 'index', name='index'),
    url(r'^test', 'test', name='test'),
    url(r'^tags/list', 'list_tags', name='list_tags'),
    url(r'^malware/get/([A-Fa-f0-9]{64})', 'get_malware', name='get_malware'),
    url(r'^malware/add', 'add_malware', name='add_malware'),
    url(r'^malware/find', 'find_malware', name='find_malware'),
    url(r'^malware/detail/(\d+)', 'detail', name='detail'),
)
