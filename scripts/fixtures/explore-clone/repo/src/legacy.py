def get_order_by_id(order_id):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
    return cursor.fetchone()
