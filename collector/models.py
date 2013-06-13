from django.db import models
from django.forms.models import model_to_dict

class tag(models.Model):
    id = models.AutoField(primary_key=True)
    tag = models.CharField(max_length=255, unique=True, db_index=True)

    def to_dict(self):
        row_dict = model_to_dict(self,fields=None,exclude=None)
        return row_dict

    def __unicode__(self):
        #return "<Tag ('%s','%s')>" % (self.id, self.tag) 
        return "ID:%s, TAG:%s" % (self.id, self.tag) 

class malware(models.Model):
    id = models.AutoField(primary_key=True)
    file_name = models.CharField(max_length=255, null=True)
    orig_url = models.CharField(max_length=1024, null=True) 
    file_size = models.IntegerField()
    file_type = models.TextField(null=True)
    md5 = models.CharField(max_length=32, db_index=True) 
    crc32 = models.CharField(max_length=8) 
    sha1 = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64, db_index=True)
    sha512 = models.CharField(max_length=128)
    ssdeep = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    tags = models.ManyToManyField("tag", db_table="collector_association", symmetrical=False)

    def to_dict(self):
        row_dict = model_to_dict(self,fields=None,exclude=None)
        return row_dict

    def __unicode__(self):
        #return "<Malware('%s','%s')>" % (self.id, self.sha1) 
        return "ID:%s, SHA1:%s" % (self.id, self.sha1) 
