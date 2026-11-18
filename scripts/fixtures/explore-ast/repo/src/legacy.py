def handler(request):
    cursor.execute("SELECT id FROM legacy WHERE id = '%s'" % request.id)
    return cursor.fetchall()
