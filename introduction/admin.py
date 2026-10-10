from django.contrib import admin
from django.contrib.auth.hashers import identify_hasher, make_password

from .models import (FAANG, AF_admin, AF_session_id, CF_user, CSRF_user_tbl,
                     comments, info, login, otp, tickits)


class HashedPasswordAdmin(admin.ModelAdmin):
    """Lab accounts whose password is checked with check_password().

    The password typed in the admin is stored as a salted Django hash (PBKDF2), never in
    clear text or as unsalted MD5. A value that is already a Django hash is kept as is.
    """

    def save_model(self, request, obj, form, change):
        try:
            identify_hasher(obj.password)
        except ValueError:
            obj.password = make_password(obj.password)
        super().save_model(request, obj, form, change)


# Register your models here.
admin.site.register(FAANG)
admin.site.register(info)
admin.site.register(login)
admin.site.register(comments)
admin.site.register(otp)
admin.site.register(tickits)
admin.site.register(CF_user, HashedPasswordAdmin)
admin.site.register(AF_admin)
admin.site.register(AF_session_id)
admin.site.register(CSRF_user_tbl, HashedPasswordAdmin)
