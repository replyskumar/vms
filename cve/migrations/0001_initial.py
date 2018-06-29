# Generated by Django 2.0.5 on 2018-06-21 09:34

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('cpe', '0001_initial'),
        ('products', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='affects',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('custom_score', models.DecimalField(decimal_places=1, max_digits=3)),
                ('comments', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now=True)),
                ('c2s', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cpe.component_to_server')),
            ],
        ),
        migrations.CreateModel(
            name='vulnerability',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('cve_id', models.CharField(max_length=16)),
                ('summary', models.TextField()),
                ('published', models.DateTimeField()),
                ('last_modified', models.DateTimeField()),
                ('score_v3', models.DecimalField(decimal_places=1, max_digits=3)),
                ('score_v2', models.DecimalField(decimal_places=1, max_digits=3)),
                ('vector_string_v2', models.CharField(max_length=100)),
                ('vector_string_v3', models.CharField(max_length=100)),
                ('in_date', models.DateTimeField(auto_now_add=True)),
                ('timestamp', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AddField(
            model_name='affects',
            name='cve',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cve.vulnerability'),
        ),
        migrations.AddField(
            model_name='affects',
            name='server',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='products.server'),
        ),
    ]
