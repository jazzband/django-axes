# encoding: utf-8
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models

class Migration(SchemaMigration):

    def forwards(self, orm):
        
        # Adding model 'AccessAttempt'
        db.create_table('axes_accessattempt', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user_agent', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('ip_address', self.gf('django.db.models.fields.IPAddressField')(max_length=15)),
            ('get_data', self.gf('django.db.models.fields.TextField')()),
            ('post_data', self.gf('django.db.models.fields.TextField')()),
            ('http_accept', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('path_info', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('attempt_time', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('status', self.gf('django.db.models.fields.IntegerField')(default=10)),
        ))
        db.send_create_signal('axes', ['AccessAttempt'])


    def backwards(self, orm):
        
        # Deleting model 'AccessAttempt'
        db.delete_table('axes_accessattempt')


    models = {
        'axes.accessattempt': {
            'Meta': {'ordering': "['-attempt_time']", 'object_name': 'AccessAttempt'},
            'attempt_time': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'get_data': ('django.db.models.fields.TextField', [], {}),
            'http_accept': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'ip_address': ('django.db.models.fields.IPAddressField', [], {'max_length': '15'}),
            'path_info': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'post_data': ('django.db.models.fields.TextField', [], {}),
            'status': ('django.db.models.fields.IntegerField', [], {'default': '10'}),
            'user_agent': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        }
    }

    complete_apps = ['axes']
