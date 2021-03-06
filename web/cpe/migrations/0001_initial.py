# Generated by Django 2.0.5 on 2018-07-02 03:45

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('products', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='component',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('cpe_id', models.CharField(blank=True, max_length=255)),
                ('title', models.TextField(blank=True)),
                ('wfs', models.CharField(blank=True, max_length=255)),
                ('timestamp', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='component_to_server',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField(auto_now=True)),
                ('cpe', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cpe.component')),
                ('server', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='products.server')),
            ],
        ),
        migrations.CreateModel(
            name='template',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=255)),
                ('timestamp', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='template_to_cpe',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField(auto_now=True)),
                ('cpe', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cpe.component')),
                ('template', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cpe.template')),
            ],
        ),
    ]
