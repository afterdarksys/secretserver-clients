import os
from secretserver import SecretServerClient
c=SecretServerClient(os.environ['SS_LIVE_KEY'],os.environ['SS_LIVE_URL'])
c.create_secret('python-live','first',container_id=os.environ['SS_LIVE_CONTAINER'])
assert c.secret('prod/python-live')=='first'
c.update_secret('python-live','second')
assert c.secret('python-live')=='second'
record=c.get_secret('python-live')
c.assign_variable('PYTHON_LIVE','secret',record['id'],'value')
assert c.render('x=%%PYTHON_LIVE%%')=='x=second'
assert c.resolve_document({'password':'%%PYTHON_LIVE%%','count':2})=={'password':'second','count':2}
assert c.get_variable('PYTHON_LIVE')['secret_id']==record['id']
assert any(v['name']=='PYTHON_LIVE' for v in c.list_variables())
c.delete_variable('PYTHON_LIVE')
c.delete_secret('python-live')
print('Python live contract PASS')
