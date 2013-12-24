pip install django==1.5.5
pip install django-axes
mkdir -p logs db media media/static
cp example/local_settings.example example/local_settings.py
python example/manage.py collectstatic --noinput
python example/manage.py syncdb --noinput
python example/manage.py axes_create_test_data
