ckanext-custom_auth allows you to reuse CKAN as the authentication backend for external applications.

## Features

- Exposes a `user_login` API action that accepts either username or email plus password.
- Returns the serialized CKAN user on success, mirroring CKAN core behaviour.
- Optionally refreshes and returns a dedicated frontend API token on each login.

## Requirements

- CKAN 2.10 (or later) with the classic auth stack enabled.

## Installation

1. Activate your CKAN virtual environment, for example:

          . /usr/lib/ckan/default/bin/activate

2. Install the extension directly from this repository:

          pip install --no-cache-dir -e git+https://github.com/pedritogonzalez88/ckanext-custom_auth.git#egg=ckanext-custom_auth

3. Enable the plugin by adding `custom_auth` to the `ckan.plugins` setting in your CKAN configuration file (typically `/etc/ckan/default/production.ini`).

4. Restart CKAN. For deployments that use Apache on Ubuntu:

          sudo service apache2 reload

## Usage

Call the CKAN action API with a POST request:

- Endpoint: `http://<ckan-host>:5000/api/3/action/user_login`
- Body:

   ```json
   {
      "id": "username-or-email",
      "password": "secret"
   }
   ```

On success the action returns the CKAN user object. When the optional frontend token is enabled (see below) the response contains an extra `frontend_token` attribute:

```json
{
   "success": true,
   "result": {
      "name": "ckan_user",
      "email": "user@example.com",
      "frontend_token": "<token-if-enabled>",
      "...": "other CKAN user fields"
   }
}
```

Authentication errors return the standard CKAN action error payload with `auth` entries in both `errors` and `error_summary`.

### Sample integration

```javascript
const loginViaCkan = async (credentials) => {
   const response = await fetch('http://ckan:5000/api/3/action/user_login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
   });

   const body = await response.json();
   return body.success ? body.result : null;
};
```

## Configuration

Set the following option to automatically rotate a dedicated frontend token on each successful login. The token is revoked just before the new one is issued and returned as `frontend_token` in the `user_login` result:

    ckanext.custom_auth.include_frontend_login_token = True

> **Note**
> CKAN does not revoke this token on logout. The extension revokes the previous token the next time the same user logs in.