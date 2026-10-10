from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('introduction', '0021_csrf_user_tbl'),
    ]

    operations = [
        migrations.AddField(
            model_name='blogs',
            name='content',
            field=models.TextField(blank=True, default=''),
        ),
    ]
