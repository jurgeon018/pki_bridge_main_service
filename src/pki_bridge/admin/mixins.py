

base_filter_fields = [
    'created',
    'created_by',
    'updated',
    'last_updated_by',
]

base_fields = [
    'created',
    'created_by',
    'updated',
    'last_updated_by',
]

class BaseMixin(object):
    save_on_top = True

    def save_model(self, request, obj, form, change):
        if change:
            obj.last_updated_by = request.user
        else:
            obj.created_by = request.user
        # if not obj.created_by:
        #     obj.created_by = request.user
        super().save_model(request, obj, form, change)

    def save_formset_additional(self, obj, form, formset, change):
        # if hasattr(obj, 'status'):
        #     obj.status = form['status']
        return obj

    def save_formset(self, request, form, formset, change):
        instances = formset.save(commit=False)
        for instance in instances:
            if change:
                instance.last_updated_by = request.user
            else:
                instance.created_by = request.user
            if not instance.created_by:
                instance.created_by = request.user
            instance.save()
        # formset.save()
        for f in formset.forms:
            obj = f.instance
            obj = self.save_formset_additional(obj, form, formset, change)
            if change:
                obj.last_updated_by = request.user
            else:
                obj.created_by = request.user
            if not obj.created_by:
                obj.created_by = request.user
            obj.save()

    def get_readonly_fields(self, request, obj):
        readonly_fields = list(super().get_readonly_fields(request))
        readonly_fields.extend([
            *base_fields
        ])
        return readonly_fields

    def get_list_filter(self, request):
        list_filter = list(super().get_list_filter(request))
        list_filter.extend([
            *base_filter_fields,
        ])
        return list_filter
