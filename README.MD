# Flask Asterisk AMI

Install the requirements, and setup the database before starting the server.

```python
>>> from flask_ami import db, Route
>>> db.create_all()
>>> Route.query.all()
[]
```

## Routes

### Creating new routes

```python
>>> route1 = Route(storeID='S12345', nexmoDID='3159556969', apiServer='http://127.0.0.1')
>>> route2 = Route(storeID='S98765', nexmoDID='3122135969', apiServer='http://45.76.151.11')
>>> db.session.add(route1)
>>> db.session.add(route2)
>>> db.session.commit()
```

### Printing all routes

```python
>>> for route in Route.query.all():
...     print(route)
...
Route(storeID: S12345, nexmoDID: 3159556969, apiServer: http://127.0.0.1)
Route(storeID: S98765, nexmoDID: 3122135969, apiServer: http://45.76.151.11)
```

### Updating a route

```python
>>> route = Route.query.filter_by(storeID='S12345').first()
>>> route
Route(storeID: S12345, nexmoDID: 3159556969, apiServer: http://127.0.0.1)
>>> route.apiServer = 'http://192.168.10.0'
>>> db.session.commit()  # To save the changes
>>> for route in Route.query.all():
...     print(route)
...
Route(storeID: S12345, nexmoDID: 3159556969, apiServer: http://192.168.10.0)
Route(storeID: S98765, nexmoDID: 3122135969, apiServer: http://45.76.151.11)
```

### Deleting a route

```python
>>> route = Route.query.filter_by(apiServer='http://45.76.151.11').first()
>>> route
Route(storeID: S98765, nexmoDID: 3122135969, apiServer: http://45.76.151.11)
>>> db.session.delete(route)
>>> db.session.commit()
>>> for route in Route.query.all():
...     print(route)
...
Route(storeID: S12345, nexmoDID: 3159556969, apiServer: http://192.168.10.0)
```

Use `filter_by` to filter out the results based on a particular field.
